# Known Limitations

This document lists known gaps in the v1 build, with honest framing on why they exist and what would close them. The goal is transparency about what this prototype does and does not do — a v1 EDR is not a v5 EDR, and pretending otherwise would undermine the rest of the project.

Items are roughly ordered by impact on detection coverage.

---

## 32-bit process visibility (AgentTesla and similar samples)

Write and `VirtualProtect` events are emitted by a user-mode hook DLL injected on process create. The current build ships an x64-only hook DLL, so 32-bit processes inject without the hook and bypass write/protect telemetry entirely.

Kernel callbacks still observe these processes — handle opens, thread creates, process create/exit are bitness-independent at the kernel callback level. So the EDR is not blind to 32-bit malware; it sees less of the chain. With write/protect missing, a 32-bit hollowing chain typically does not accumulate enough score to cross the alert threshold.

In practice: AgentTesla detonates cleanly under the current build with kernel-level telemetry visible, but no `[ALERT]` fires.

**Closing the gap (v2):**

- Build a 32-bit hook DLL alongside the x64 one. Architecturally clean; doubles the DLL maintenance surface.
- ETW Threat-Intelligence (ETW-TI) supplements user-mode hooks with kernel-sourced bitness-independent events. Out of reach for this project (requires PPL-AntiMalware code-signing, vendor-only) but worth noting as the production-grade alternative.

---

## Hook injection skip list is filename-substring matched

`output.cpp` (and related sites) maintains a list of process names that don't get the hook DLL injected. The match is currently a filename substring check, so a renamed `evil.exe → explorer.exe` placed anywhere on disk would dodge hook injection.

Severity is moderate, not severe: kernel callbacks still see these processes regardless of name. Hook bypass costs the EDR write/protect visibility on that specific process, not all visibility.

**Closing the gap (v2):** Reuse the path-normalization + trusted-directory + LOLBin pattern already in `IsTrustedSystemSource` (see `detections.cpp`). Refactor those helpers into a shared utility so the hook injection skip list and the trust subsystem use the same path-aware matching.

---

## PowerShell parent-child chains can produce false-positive alerts

During validation (notably the SnakeKeylogger detonation), the EDR fired ALERTs on `powershell.exe(parent) → powershell.exe(child)` chains where the relationship was a normal `CreateProcess` — the user typed `powershell .\snake.ps1` from an existing PowerShell prompt, and the parent-child pair scored injection primitives high enough to cross threshold (150–180) despite no actual injection occurring between them.

These FPs are *additional* to the genuine `powershell → Aspnet_compiler.exe` hollowing alerts the sample is supposed to trigger. The malicious chain is detected correctly; the parent-child PowerShell pair is spurious.

Root cause not fully isolated in v1. The most likely candidate is an over-weighted "parent writes into fresh child" bonus that fires on PowerShell's child-initialization traffic — runspace setup and .NET host plumbing perform cross-process writes shortly after `CreateProcess`, which the chain logic currently scores the same as malicious writes.

**Closing the gap (v2):** Reproduce outside a malware detonation — spawn a benign PowerShell child from a benign PowerShell parent and check whether the chain still alerts. If yes, retune the parent-child write bonus or add a young-child age suppressor so normal `CreateProcess` init traffic doesn't score.

---

## Authenticode trust accepts any valid signer, not Microsoft specifically

`IsTrustedSystemSource` accepts a binary as trusted if it lives in a system directory, is not on the LOLBin denylist, and has a valid Authenticode signature (embedded or catalog). It does **not** verify the signer is Microsoft.

In practice this means: a third-party signed binary placed in `C:\Windows\System32` (rare, but not impossible — vendor-installed system tools, driver helpers, antivirus components) would be trusted. The user-permission model already restricts who can write to `System32`, so the practical risk is low, but the trust gate could be tighter.

**Closing the gap (v2):** Extract the cert chain from the `WinVerifyTrust` state and pin on subject (e.g., "Microsoft Windows", "Microsoft Corporation"). The plumbing exists — `WTGetSignatureSettings` / `CryptQueryObject` — it's just not wired up.

---

## Hijacked trusted process is suppressed by trust gate

By design, the trust gate suppresses alerts where the source process is a signed system binary. This means: if a real attacker successfully hollows or DLL-hijacks `explorer.exe` (or any other trusted process) and uses it to inject elsewhere, the resulting injection chain would be silently bypassed.

This is a known weakness of every signature-based trust pattern — including production EDRs. Trust-by-identity assumes process identity is the attacker's bottleneck, which it isn't always.

**Closing the gap (v2):** Anomaly detection on trusted processes. Examples: explorer.exe writing to a private RX page in a small region is suspicious *even though* explorer is trusted; svchost.exe spawning `cmd.exe` is suspicious even though both are signed Microsoft binaries. The trust subsystem becomes a "default suppress" rather than an "absolute suppress."

---

## `sawThread` flag blocks late-binding write→thread match

Currently in `DetectionThreadEvent`, the first executing thread for a (src→dst) chain sets `sawThread=TRUE` and early-returns, blocking later threads from contributing to the score. This means: if the entry-point thread fires before the first write, the `startMatchesWrite` check (which looks for a thread starting at a previously-written address) never gets a chance on later threads — even after a write populates `s->writeAddr`.

Pattern: any sample that creates threads and writes in non-canonical order would lose the `startMatchesWrite` signal.

**Closing the gap (v2):** Split the dedup. Keep `sawThread` for one-time primitive bumps (image_exec / private_exec scoring, which only count once per chain). Allow `startMatchesWrite` to fire on later threads as a separate gated bonus, with its own flag (`sawStartMatchesWrite`).

---

## Single-DOS-volume path normalization

`ToDosPath` translates `\Device\HarddiskVolumeN\...` paths to DOS form by enumerating drive letters and matching prefixes. This works on standard single-volume installs. It would not handle:

- Junctions and symlinks (path normalization does not resolve them)
- Per-user mapped drives if the EDR runs under a different session
- BitLocker / removable / unusual volume configurations

In practice this manifests as `path_normalize_failed` (silent — the trust gate fails closed). Untrusted-by-default failure mode means the cost of a normalization miss is a *false alert*, never a missed detection.

**Closing the gap (v2):** Resolve via `GetFinalPathNameByHandle` after opening the file. More robust, slightly slower; cache absorbs the cost.

---

## `IOCTL_EDR_RESOLVE_CREATETIME` is per-thread-event

Resolving target process create-time happens on every thread event via a userland → kernel → userland round trip. Hasn't been a problem at typical event rates, but heavy thread-create load (e.g., a benchmark process spawning thousands of threads) would surface latency. No measurements yet.

**Closing the gap (v2):** Cache create-time per (pid, dst) in the `INJECT_STATE` slot — already populated on first observation, just not reused. One-line fix; deferred only because it hasn't bitten.

---

## Catalog signature success path emits no diagnostic

The catalog signature dispatcher tries SHA-256 first, falls back to SHA-1. Both algos are tried silently; only the final TRUE/FALSE is observable. If a catalog is ever revoked, corrupted, or fails for an unexpected reason, there's no log trail to investigate after the fact.

**Closing the gap (v2):** Add a debug-flag-gated success log. Off by default in production builds; on by default in dev builds.

---

## Test injector is a separate component, not detected by name

The development test injector (a small tool that performs a known-good remote thread injection into a target, used to validate the EDR end-to-end) is not bundled in this repo. It's intentionally kept out — the EDR is the artifact; the injector is the test fixture.

The EDR detects the test injector cleanly via the same chain logic that detects real malware. This is noted only because anyone reproducing the test setup will need to write or supply their own injector.

---

## Detection coverage

Current build detects three injection techniques with high confidence:

- **Process Hollowing** (T1055.012)
- **Shellcode Remote Thread** (T1055)
- **Image-Based Injection**

Out of scope for v1, deferred to future iterations:

- **DLL Sideloading** (T1574.002) — file-system-side detection; needs minifilter
- **APC Injection** (T1055.004) — needs an `NtQueueApcThread` user-mode hook (or ETW-TI's APC events)
- **AtomBombing** / **Process Doppelgänging** — exotic; would need section-object telemetry
- **Manual mapping / reflective loading** in scenarios where no module mapping events fire — partial coverage today via private-RX region scoring; not validated against representative samples

---

## Telemetry surfaces not yet implemented

The kernel driver currently provides process, thread, handle, and memory event telemetry. Two additional surfaces are scoped but not built:

- **Filesystem minifilter** — for ransomware-style mass-rename / mass-encrypt detection, suspicious LOLBin file drops, persistence locations.
- **Windows Filtering Platform (WFP) callouts** — for network-side detection: C2 beaconing, exfiltration, lateral movement attempts.

Both are roadmap items, not bugs. Mentioned here so readers understand the scope of v1.

---

## Response automation not implemented

This is the "D" of EDR — detection only. There is no response capability in v1: no process termination on alert, no network isolation, no file quarantine, no remediation playbooks. Alerts are written to the log; humans (or downstream tooling) act on them.

This is intentional scope, not oversight. Response involves a different threat model: who can trigger a kill, what permissions the response runs under, how to avoid breaking the host on a false positive, how to handle race conditions where the malicious thread has already executed by the time the alert fires. None of that is technically prohibitive, but all of it deserves its own thinking pass rather than being bolted on.

**Closing the gap (v2):** A response module sitting downstream of the alert pipeline. Initial scope: terminate the destination process on `[ALERT]`, with a kill-list whitelist (don't terminate `lsass.exe` even if it's the dst), confidence threshold (only HIGH confidence triggers automation), and an off-by-default flag so the EDR ships safe by default. Network isolation and file quarantine are bigger; v3+.

---

## Development context

This project was built solo over approximately three months as a learning exercise and portfolio piece, with AI-assisted iteration (see README). Architectural decisions, malware sample selection, and validation methodology were driven by the author; implementation was iterative collaboration. Each detection layer was empirically validated against real malware samples before moving to the next.

Some of the limitations above reflect deliberate scoping choices (e.g., not implementing ETW-TI because the signing requirement is structural, not technical). Others reflect things that simply didn't fit in the v1 timeline (e.g., minifilter, WFP). The `v2` framing is not a roadmap commitment — it's an honest accounting of what would close each specific gap.

---

## Code organization / refactoring backlog

These don't affect detection capability — they're code-quality items I know about and intend to address. Documenting them here so the gap is visible rather than hidden.

### Hardcoded DLL path duplicated across files

`L"C:\\drivers\\EDRHookClean.dll"` appears as a string literal in `main.cpp`, `output.cpp`, and `EDRClient.cpp`. Same for `C:\\drivers\\edr_log.txt` in `output.cpp`. Should be centralized to `#define EDR_DLL_PATH` and `#define EDR_LOG_PATH` in `shared.h`.

**Why it matters:** changing the install path requires editing three sites. A drift between them would silently break injection on whichever path got missed.

### Injection skip list duplicated in two files

The skip list (kernel pseudo-processes, structurally-essential system processes, EDRClient itself, dev tools) is open-coded as an `_wcsicmp` cascade in both `main.cpp` (startup snapshot loop) and `output.cpp` (runtime `PROCESS_CREATE` handler). Should be a single `BOOL ShouldSkipInjection(const wchar_t* exeName)` helper in `edrclient.h`.

**Why it matters:** the existing limitation about filename-substring matching being fragile (see above) should be fixed in *one* place when it gets fixed. Two implementations means two opportunities for drift.

### Dev-environment entries leaking into the skip list

`OSRLOADER.exe` and `Dbgview.exe` are tools used on the kernel-development host (OSR's driver loader and Sysinternals DBGView). They were added to suppress noise during development and never removed. They're harmless outside that environment but are visible in source. Will be cleaned up alongside the skip-list refactor.

### Driver init silent partial-failure

In `DriverEntry`, if `PsSetCreateProcessNotifyRoutineEx` or `PsSetLoadImageNotifyRoutine` fail to register, the driver logs the failure via `DbgPrint` but still returns `STATUS_SUCCESS` and proceeds. The result is a driver that loads with degraded telemetry and gives the operator no clear signal that something is wrong. Should fail loudly — either return the failing status, or at minimum mark the partial-failure state in a queryable way.