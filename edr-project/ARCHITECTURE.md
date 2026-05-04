# Architecture

This document explains how the EDR works, the design decisions behind it, and the rationale for major scope choices. It's written for a technical reader — someone reading the source code who wants the mental model first.

For what it detects (and what it doesn't), see [`DETECTIONS.md`](DETECTIONS.md). For honest scope boundaries, see [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).

---

## 1. System overview

The EDR consists of three components:

```
   ┌──────────────────────────────┐
   │  Kernel driver  (kernel/)    │   ← MyEDR.sys
   │                              │
   │  Registers 4 callbacks:      │
   │    - PsSetCreateProcessNotify│
   │    - PsSetCreateThreadNotify │
   │    - PsSetLoadImageNotify    │
   │    - ObRegisterCallbacks     │
   │                              │
   │  Emits EDR_EVENTs into a     │
   │  16384-slot ring buffer      │
   │  (EVENT_QUEUE, spinlock-     │
   │  protected).                 │
   └─────────────┬────────────────┘
                 │ IRP_MJ_READ / IOCTL
                 │ via \\.\MyEDR
                 ▼
   ┌──────────────────────────────┐
   │  Userland client             │   ← EDRClient.exe
   │  (usermode/client/)          │
   │                              │
   │  - Drains ring buffer        │
   │  - Resolves SECCTX           │
   │    (token, integrity, privs) │
   │  - Injects hook DLL into     │
   │    every running process     │
   │  - Tracks chains in          │
   │    INJECT_STATE slots        │
   │  - Scoring + alerting        │
   └─────────────┬────────────────┘
                 │ inject + IPC (DeviceIoControl
                 │ for cross-process create-time
                 │ resolution)
                 ▼
   ┌──────────────────────────────┐
   │  Hook DLL                    │   ← EDRHookClean.dll
   │  (usermode/dll/)             │
   │                              │
   │  Loaded into (almost) every  │
   │  userland process.           │
   │  Inline-hooks 3 Nt syscalls  │
   │  and forwards every call to  │
   │  the client via the driver   │
   │  as WRITE/PROTECT/RESUME     │
   │  events.                     │
   └──────────────────────────────┘
```

Three components, three roles:

- **Kernel driver:** broad telemetry (process / thread / image / handle) at zero performance cost, surfaces it without bias toward a specific detection.
- **Userland client:** orchestrates everything — drains kernel events, runs detection logic, manages chain state, fires alerts, manages the hook DLL.
- **Hook DLL:** fills in the gap kernel callbacks can't cover by themselves: per-syscall write/protect/resume granularity, in the address space of the calling process.

This split mirrors how production EDRs are built. Kernel for what's easy in kernel; user-mode for what's only practical from user-mode; one orchestrator that joins them.

---

## 2. Telemetry sources

### Kernel callbacks

Four standard Windows kernel callback types, all registered in `DriverEntry` (`kernel/driver.c`):

| Callback                          | Purpose                              | Emits event types                        |
|-----------------------------------|--------------------------------------|------------------------------------------|
| `PsSetCreateProcessNotifyRoutineEx` | Process create / exit notifications | `EDR_EVENT_PROCESS_CREATE`, `EDR_EVENT_PROCESS_EXIT` |
| `PsSetCreateThreadNotifyRoutine`  | Thread creation                      | `EDR_EVENT_THREAD_CREATE`                |
| `PsSetLoadImageNotifyRoutine`     | DLL / EXE image loads                | (currently informational; populates module data)   |
| `ObRegisterCallbacks` (process)   | Handle creation against process objects | `EDR_EVENT_HANDLE_OPEN`               |

These four cover the entire process / thread / handle lifecycle and are bitness-independent (32-bit and 64-bit processes are equally observable). They're the bedrock of the chain detector.

### User-mode hook DLL

Three Nt-layer syscalls hooked via inline trampoline in `usermode/dll/inline_hook.cpp`:

| Hook                          | Why it's hooked                       | Emits event type                  |
|-------------------------------|---------------------------------------|-----------------------------------|
| `NtWriteVirtualMemory`        | Catches writes to remote process memory (the data plant in injection) | `EDR_EVENT_WRITE_MEMORY`     |
| `NtProtectVirtualMemory`      | Catches RW→RX flips (preparing shellcode regions for execution)        | `EDR_EVENT_PROTECT_MEMORY`   |
| `NtResumeThread`              | Catches the "go" signal in process hollowing (resume after image swap) | `EDR_EVENT_RESUME_THREAD`    |

**Why hook at Nt-layer rather than the Win32 wrapper:** every Win32 API like `WriteProcessMemory` ultimately reduces to `NtWriteVirtualMemory`. Hooking at the lower layer catches both well-behaved Win32 callers *and* malware that calls the Nt layer directly to evade Win32 hooks. It's a common boundary for user-mode EDR-style hooking because it sits close to the syscall ABI.

**Why not ETW Threat-Intelligence (ETW-TI):** ETW-TI provides bitness-independent, kernel-sourced write / protect / resume events, which would be a strict upgrade over user-mode hooking. But subscribing to ETW-TI requires a binary signed for `PROCESS_PROTECTED_ANTIMALWARE_LIGHT` (PPL-AntiMalware), and Microsoft only grants that signing privilege to formal AV vendors. As an individual building a learning prototype, ETW-TI is out of reach — not for technical reasons, but for code-signing-policy reasons.

### Event flow

```
[Kernel callback fires]
         │
         ▼
[InsertEvent() in kernel/events.c]
   - acquires g_EventQueue.Lock spinlock
   - writes EDR_EVENT into ring buffer (16384 slots)
   - advances Head; releases spinlock
         │
         ▼
[Userland EDRClient main loop, in usermode/client/main.cpp]
   - blocks on DeviceRead() — IRP_MJ_READ over \\.\MyEDR
   - kernel hands back up to 512 events per drain
   - for each event: HandleEvent(evt) routes to
     the matching Detection*Event handler in detections.cpp
         │
         ▼
[Detection handler, in usermode/client/detections.cpp]
   - looks up or creates an INJECT_STATE for (src, dst, srcCT, dstCT)
   - bumps score based on observed primitive
   - checks score thresholds:
       60 → [SUSPICIOUS] (after trust gate)
       80 → [ALERT]      (after trust gate)
```

The hook DLL piggybacks on this same flow. When `NtWriteVirtualMemory` fires inside an injected process, the hook handler calls back into the EDR via the driver, which inserts a `WRITE_MEMORY` event into the same ring buffer that kernel callbacks use. From the detection side, kernel events and hook events are fully fungible — it's all one stream.

---

## 3. Chain state machine: `INJECT_STATE`

All injection-detection logic in `usermode/client/detections.cpp` revolves around the `INJECT_STATE` struct: one slot per `(source PID, destination PID, source createTime, destination createTime)` tuple. The 4-tuple key matters — PIDs alone are not enough, because Windows recycles them aggressively, and a stale chain from a long-dead PID would otherwise corrupt scoring on a fresh process that happened to inherit the PID.

Each slot tracks:

- **Primitive flags** (`sawHandle`, `sawWrite`, `sawThread`, `sawProtect`, `sawResume`) — which primitive events have already been observed for this chain
- **Write metadata** — last write address, last write size, write time (for `startMatchesWrite` correlation: a thread starting at a previously-written address)
- **Score** — an integer accumulator, starts at 0, bumped when scoring conditions match
- **`lastSeen`** — used to expire stale chains (a 30-second silence drops 20 score; chains hitting 0 or below are zeroed out)
- **`alerted`** — has this chain already fired an alert? (so it doesn't re-alert on every subsequent event)
- **`loggedSuspicious`** — has the SUSPICIOUS line been emitted for this chain? (one-per-chain dedup; emit-on-every-event would flood logs)
- **`sourceTrust`** — per-chain trust verdict cache (UNCHECKED / TRUSTED / UNTRUSTED). See §5.

A new event arrives, the handler:

1. Resolves the chain slot via `GetState(src, dst, srcCT, dstCT)` (or creates one if absent)
2. Optionally bumps the score based on the primitive observed and any contextual scoring (parent-child, tiny-private-region, etc.)
3. At score thresholds (60 SUSPICIOUS, 80 ALERT), checks the trust gate before emitting

Stale chains are cleaned up via two mechanisms: timeout decay inside per-event handlers, and `CleanupStaleInjectStates()` called once per main-loop iteration.

---

## 4. Scoring model

This is rules-based, intentionally — every score change is auditable. No ML (machine learning), no opaque thresholds, every weight is set by hand and justified by the malware behavior it's meant to catch.   
Weights and thresholds will be retuned as additional telemetry sources are added — adding minifilter (filesystem) or WFP (network) telemetry would change the optimal scoring model.

The current model uses these primitives and bonuses (read `usermode/client/detections.cpp` for ground truth):

| Signal                                          | Score | Notes                                                     |
|-------------------------------------------------|-------|-----------------------------------------------------------|
| Handle to remote process opened with dangerous access mask | +20   | `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD` |
| Parent-child handle context bonus               | +10   | Source is parent of destination AND destination is recently created |
| Write to remote process memory                  | +30   | Counted once per chain (via `sawWrite`)                   |
| Parent → child write (hollowing pattern)        | +50   | Specifically the parent-to-child case; sharply different from one-off writes |
| Protect to private executable region            | +20   | Counted once per chain                                    |
| Tiny private-exec region bonus                  | +10   | Region size ≤ 0x1000 — distinctive of shellcode plants    |
| Thread create where execution begins            | +50   | Image-exec or private-exec destination (each counted once)|
| `startMatchesWrite` — thread starts at recently-written address | (bonus) | Nuanced timing match between WRITE and CREATE_THREAD |
| Resume thread on suspended target               | +50   | The "execute" trigger in process hollowing                |
| `lastSeen` timeout (30s of silence)             | -20   | Chains decay to 0 and get cleaned up                      |

A clean shellcode-remote-thread chain reaches the alert threshold via: handle (+20) → write (+30) → thread (+50) = score 100. A clean process-hollowing chain reaches it via: handle (+20) → write (+30) → parent-child write bonus (+50) → resume (+50) = score 150.

**Why thresholds at 60 and 80:**

- 60 is "two real primitives observed" — enough to call it `[SUSPICIOUS]` and leave a forensic trail, but not enough to claim execution. SUSPICIOUS is for the case where execution gets missed (direct syscalls, hook bypass, race conditions): even if we don't see the alert-worthy event, we want a record of what we *did* see.
- 80 is "alertable" — typically requires a primitive that strongly implies execution (`THREAD_CREATE` on a private-exec region, or `RESUME_THREAD` on a hollowed target).

These thresholds were tuned empirically against real malware and a baseline of normal Windows activity.

---

## 5. The trust subsystem

This is the largest single feature in the userland client. It exists to solve one problem: **scoring rules sometimes match legitimate Windows behavior.** Without trust suppression, normal system processes — Windows Update notifiers, taskhost orchestrators, login flows — would generate a steady drip of false positives.

### Why not just whitelist by name?

The naive approach is "if source process is `MusNotification.exe`, suppress the alert." This is trivially bypassable: drop a renamed `evil.exe → MusNotification.exe` in `C:\Users\Public\` and you're past the gate. Anything that decides on filename alone is broken.

So the trust check is layered, ordered cheapest-to-most-expensive, fail-closed at every layer:

```
                Source process for a chain hitting SUSPICIOUS or ALERT
                                       │
                                       ▼
              ┌───────────────────────────────────────────────┐
              │  Layer 1: Path normalization (ToDosPath)      │
              │  \??\… or \Device\HarddiskVolumeN\… → DOS path│
              │  Fail → not trusted                           │
              └───────────────────┬───────────────────────────┘
                                  ▼
              ┌───────────────────────────────────────────────┐
              │  Layer 2: Trusted system directory prefix     │
              │  Must be under System32, SysWOW64, WinSxS,    │
              │  Program Files, or Program Files (x86).       │
              │  Fail → not trusted                           │
              └───────────────────┬───────────────────────────┘
                                  ▼
              ┌───────────────────────────────────────────────┐
              │  Layer 3: LOLBin denylist                     │
              │  cmd, powershell, pwsh, wscript, cscript,     │
              │  mshta, regsvr32, rundll32.                   │
              │  Even signed Microsoft binaries on this list  │
              │  do NOT get a trust pass.                     │
              │  Match → not trusted                          │
              │  No Match → continue                          │
              └───────────────────┬───────────────────────────┘
                                  ▼
              ┌───────────────────────────────────────────────┐
              │  Layer 4: Authenticode signature              │
              │  4a: VerifyEmbeddedSignature (PE cert table)  │
              │  4b: VerifyCatalogSignature                   │
              │      - try SHA-256 catalog                    │
              │      - fall back to SHA-1 catalog             │
              │  Either path verifies → trusted               │
              │  Both fail → not trusted                      │
              └───────────────────┬───────────────────────────┘
                                  ▼
                              [Trusted]
                          → suppress alert
                          → emit [TRUST_BYPASS] for forensic trail
```

### Embedded vs catalog signatures

Windows signs system binaries two ways. The fast path is **embedded signing**: signature lives in the PE certificate table, `WinVerifyTrust` with `WTD_CHOICE_FILE` checks it. Examples: chrome.exe, taskhostw.exe, third-party signed apps.

Many Microsoft system binaries — including `MusNotification.exe`, `ntdll.dll`, much of `System32` — have **no embedded signature.** Their signatures live in security catalog files under `C:\Windows\System32\CatRoot\`. Verification is more involved:

1. Compute the file hash
2. Enumerate catalogs containing that hash (`CryptCATAdminEnumCatalogFromHash`)
3. Hand the catalog reference to `WinVerifyTrust` with `WTD_CHOICE_CATALOG`

Catalog entries can use either SHA-1 (legacy) or SHA-256 (modern). A single binary appears in only one. The implementation tries SHA-256 first, falls back to SHA-1 if SHA-256 finds no matching catalog. Both algos silent on success; both silent on failure (the dispatcher return value is the signal).

Catalog support was deliberately added because the first version of the trust subsystem used embedded verification only — and during validation it became clear that *most of System32 fails embedded verify*. Skipping catalog support would have meant the trust subsystem only protected against FPs from a third of system binaries. Implementing catalog support raised that to "essentially all of them."

### Caching

Two-level cache:

- **Path-level (`g_TrustCache`):** `std::map<std::wstring, BOOL>` keyed on full DOS path. `WinVerifyTrust` runs at most once per unique image across the entire EDR session. Authenticode verification is slow (file I/O + hash + catalog lookup); cache hits are sub-microsecond map lookups.
- **Per-chain (`INJECT_STATE.sourceTrust`):** UNCHECKED / TRUSTED / UNTRUSTED on the chain slot. The first decision-point event in a chain populates it; subsequent events reuse it without even hitting the path cache.

Net: in a session with many MusNotification chains, `WinVerifyTrust` runs exactly *once*, regardless of chain count.

### What the trust gate does NOT protect against

If a real attacker hijacks `explorer.exe` itself — DLL hijacking, classic reflective injection into a trusted process — and uses it to inject elsewhere, the trust gate suppresses the alert. This is a known weakness of *every* signature-based trust pattern, including production EDRs. It's listed in `KNOWN_LIMITATIONS.md` and the v2 path is anomaly detection on trusted processes (e.g., "signed-Microsoft-explorer is writing to a tiny private-RX region — that's unusual *even though* explorer is trusted").

---

## 6. Hook DLL: design and lifecycle

The hook DLL (`usermode/dll/`) is loaded into (almost) every running userland process. It uses inline trampoline hooks to redirect three syscalls into local handler functions.

### Loading

On EDRClient startup, the client enumerates all running processes (`Toolhelp32Snapshot`), filters out a hardcoded skip list (kernel processes, EDRClient itself, and a small set of structurally-essential processes like `services.exe`, `lsass.exe`, `csrss.exe`, `winlogon.exe`, `wininit.exe`, `smss.exe`, `explorer.exe`, the system PIDs 0/4), and injects the DLL into each survivor via `CreateRemoteThread(LoadLibrary)`.

For processes created *after* startup, the client tracks `PROCESS_CREATE` events from the kernel and injects into newly-spawned processes the same way. Suspended processes (created with `CREATE_SUSPENDED`) defer injection until they resume — injecting into a suspended process is unsafe because Windows hasn't initialized the loader for that thread yet.

### Inline trampoline hooks

The hook implementation patches the first few bytes of each target syscall with a 14-byte absolute jump (`FF 25 00 00 00 00 + 8-byte address`) into the hook handler. The displaced bytes are copied into a separately-allocated trampoline along with a tail jump back into the original function past the patch site, so the handler can call the original without recursing into itself.

Reentrancy is managed via per-thread guard flags: when the hook handler itself calls into APIs that might reach the hooked syscall (logging, e.g.), the guard prevents re-entry. The trampoline path bypasses the patch entirely, so calling `forward(...)` from the handler doesn't trigger the hook again.

This is the same general approach Microsoft Detours uses, and a common approach for user-mode telemetry in EDR-style tools. The implementation here is a from-scratch educational version — Microsoft Detours is the production answer for anyone shipping this for real.

### Why hook in user-mode at all (rather than just trust kernel callbacks)

Kernel callbacks alone don't see writes or protect-flips. `PsSetCreateProcessNotifyRoutineEx` fires on process create / exit, not on `WriteProcessMemory`. There is no kernel notification routine for "process A wrote to process B's memory." That information lives on the syscall path, which means the only practical hook points outside ETW-TI are user-mode trampolines on `Nt*VirtualMemory` syscalls.

So: kernel for the things kernel can see, user-mode hooks for the things kernel can't. This is one practical architecture for Windows telemetry when ETW-TI is unavailable.

---

## 7. SECCTX resolution: why it's deferred

When a process is created, the kernel callback fires with whatever context is available at that moment. Some metadata (token integrity, elevation type, privileges, user SID) is not yet populated by the kernel at process-create time — it's filled in later as Windows finishes setting up the process.

So the EDRClient queues a `SECCTX_WORK_ITEM` for each new process and retries token resolution on a backoff. `ProcessSecCtxQueue()` runs every main-loop iteration, attempts `OpenProcess` + `OpenProcessToken` + `GetTokenInformation`, and either marks the entry `SecCtxReady` on success or retries with increasing delay. After enough retries, the entry is dropped — most of the time the process has already exited (very short-lived processes hit this path).

This retry pattern matters because chain detection sometimes references the resolved token info (privilege model, integrity level), and if SECCTX wasn't ready in time, the detection would have to operate without it.

---

## 8. Why this architecture makes the choices it does

A few decisions worth justifying explicitly:

**Userland orchestration, kernel as a sensor.** The driver's job is to surface events fast and accurately. It does no detection logic. The detection logic lives in user-mode, where iteration is fast (no BSOD from a bad detection rule), where the language is C++ (with `std::map`, `std::wstring`), and where recovery from a bug is "EDRClient.exe restart" rather than "reboot." Many production EDR designs follow a similar split: minimal kernel surface, richer userland orchestration.

**One ring buffer, both telemetry sources.** Kernel events and hook DLL events flow into the same `g_EventQueue`, in the same `EDR_EVENT` shape. The detection code doesn't distinguish source. This keeps the chain-correlation logic uniform and means new telemetry sources (eventually: minifilter, WFP) plug in cleanly.

**Rules-based scoring rather than ML.** Every score weight is human-set, every detection has a clear "this fired because primitives X+Y+Z were observed." Auditable, debuggable, no need for a training set. This isn't a knock on ML detections — it's the right call for *this* project, where the goal is to demonstrate understanding of attack mechanics, not to compete with CrowdStrike on coverage breadth.

**4-tuple chain key (not just src+dst PID).** Windows recycles PIDs aggressively. Without the create-time pair in the key, a stale chain from a long-dead PID would corrupt scoring on a fresh process inheriting the PID. This is a real bug class — production EDRs handle it the same way.

**Trust gate as a layered fail-closed pipeline rather than a single check.** Path → directory → LOLBin → signature, in that order, with the cheapest checks first. Every layer fails closed (default to not-trusted). LOLBin denylist is critical — it's why `powershell.exe snake.ps1` doesn't get bypassed despite PowerShell being a signed Microsoft binary in System32.

---

## 9. What's not in v1

These are scoped *out* of v1 deliberately, not omitted by oversight:

- **Filesystem minifilter** — would catch ransomware-style mass-encrypt patterns and persistence drops to autoruns locations. Significant scope; v2.
- **WFP network callouts** — would catch C2 beaconing, exfil, lateral movement. Significant scope; v2.
- **ETW Threat-Intelligence** — replaces user-mode hooks with kernel-sourced bitness-independent events. Blocked on PPL-AntiMalware code-signing (vendor-only); structural, not technical.
- **Publisher-name pinning on Authenticode** — currently any valid signer is trusted. Tightening to "Microsoft Windows" / "Microsoft Corporation" is a v2 hardening.
- **Anomaly detection on trusted processes** — currently trust = absolute suppress. Layering "explorer.exe is trusted but writing to a private-RX region is still weird" needs a second pass.
- **32-bit hook DLL** — current build is x64-only. 32-bit malware (AgentTesla and similar) gets reduced visibility. Build a 32-bit DLL alongside the x64 one.

See `KNOWN_LIMITATIONS.md` for the full list with rationale and fix paths.
