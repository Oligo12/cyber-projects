# Custom Mini-EDR Project

**Status:** Lab prototype (not production-ready)                                                                                                                                                         
**Author:** Nikola Marković                                                                                                                                                
**Last updated:** 2026-04-12                                                                                                                                                
**Version:** v1                                                                                                                                                

A lightweight Windows EDR sensor built from scratch to detect process injection techniques (process hollowing, shellcode injection, remote thread creation) using kernel callbacks and userland API hooking.

Built as a learning project to understand how commercial EDR products work under the hood - from kernel telemetry collection to behavioral detection and alerting.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        KERNEL (driver.sys)                       │
│                                                                  │
│  PsSetCreateProcessNotifyRoutineEx ──► Process Create/Exit       │
│  PsSetCreateThreadNotifyRoutine    ──► Thread Creation           │
│  PsSetLoadImageNotifyRoutine       ──► Image Load                │
│  ObRegisterCallbacks               ──► Handle Open (access mask) │
│                                                                  │
│  Ring buffer (EVENT_QUEUE) ──────► DeviceRead (IRP_MJ_READ)      │
└────────────────────────────────────────┬─────────────────────────┘
                                         │ ReadFile() 
┌────────────────────────────────────────▼─────────────────────────┐
│                   USERLAND (EDRClient.exe + hook DLL)            │
│                                                                  │
│   Hook DLL (injected into processes by the client):              │
│    ► NtWriteVirtualMemory  ─┐                                    │
│    ► VirtualProtectEx       ├─► IOCTL → driver → ring buffer     │
│    ► NtResumeThread        ─┘                                    │
│                                                                  │
│  EDRClient.exe:                                                  │
│    ► Reads events from kernel ring buffer                        │
│    ► Maintains process table (PID, parent, image, privileges)    │
│    ► Enriches thread events with VirtualQueryEx                  │
│    ► Correlates handle + write + thread + protect + resume       │
│    ► Score-based injection detection engine                      │
│    ► Alerts on threshold (score ≥ 80)                            │
└──────────────────────────────────────────────────────────────────┘
```

---

## Detection Logic

The sensor uses a **score-based behavioral engine** that correlates multiple low-confidence signals into high-confidence injection alerts. Each source→target process pair accumulates a score based on observed activity:

| Signal | Score | Rationale |
|--------|-------|-----------|
| Cross-process handle with `VM_WRITE\|VM_OPERATION\|CREATE_THREAD` | +20 | Required precondition for any injection |
| Parent opening handle to own fresh child (< 5s) | +10 | Hollowing setup pattern |
| Cross-process `NtWriteVirtualMemory` | +30 | Payload delivery |
| Parent writing into its own fresh child (< 5s) | +40 | Strong hollowing signal |
| Remote thread in private executable memory (`MEM_PRIVATE + RX/RWX`) | +50 | Classic shellcode injection |
| Thread starting in `NOACCESS` / `type=0` memory | +50 | Suspended process resumed after hollowing |
| Remote thread in image-backed executable memory | +30 | Reflective DLL / image-based injection |
| Thread start address matches recent write region | +40 | Write→execute correlation |
| `NtResumeThread` shortly after `NtWriteVirtualMemory` (< 5s) | +50 | Hollowing finalization |
| Remote `VirtualProtectEx` flipping to executable | +25 | Memory permission change for injection |
| Protect after prior write to same target | +15 | Write→protect chain |
| Score decay (> 30s gap between events) | -20 | Reduces false positives from stale state |

**Alert threshold:** score ≥ 80 → `[ALERT] Remote Injection`

Technique classification:

- `PROCESS_HOLLOWING` - thread in NOACCESS/unmapped memory or resume-after-write pattern
- `SHELLCODE_REMOTE_THREAD` - thread in private executable memory
- `SHELLCODE_INJECT` - write→protect(exec) chain
- `IMAGE_BASED_INJECTION` - thread in image-backed executable memory

---

## Detection in Action: SnakeKeylogger

The sensor was validated against a real SnakeKeylogger sample - a multi-stage fileless malware that uses PowerShell → .NET reflection → process hollowing into `aspnet_compiler.exe`.

Full malware analysis: [SnakeKeylogger Report](../malware-analysis/SnakeKeylogger/Report.md)

### What the sensor saw

**Stage 1 - PowerShell parent-child self-injection (score 190)**

The initial PowerShell loader (`ppid=8104`) spawns a child PowerShell process (`pid=7340`) and immediately opens a handle with full access, writes into its memory, and creates threads - all within milliseconds:

```
[09:49:15.640] PROC_CREATE | img=powershell.exe pid=7340 pimg=powershell.exe ppid=8104
[INJECT OK] PID=7340
[09:49:15.640] HANDLE_OPEN | src=powershell.exe spid=8104 tgt=powershell.exe tpid=7340
                             access=VM_WRITE|VM_OPERATION|CREATE_THREAD raw=0x001FFFFF type=write
[MEM][IMAGE_EXEC] SRC=8104 DST=7340 START=00007FF7259C3D40 BASE=00007FF7259C3000 SIZE=28672 TYPE=MEM_IMAGE PROTECT=RX
[09:49:15.640] THREAD_CREATE | img=powershell.exe pid=7340 tid=3400
                               start=00007FF7259C3D40 base=00007FF7259C3000 size=28672 type=MEM_IMAGE prot=RX

[ALERT] Remote Injection | src=powershell.exe(8104) dst=powershell.exe(7340)
         technique=PROCESS_HOLLOWING confidence=HIGH score=190
```

> **Note:** Score is inflated - `ObRegisterCallbacks` fires multiple handle events per logical action during process creation, and the engine currently scores each one. With handle deduplication (one score bump per src→dst pair), this would alert at ~130 via the write path instead, which is a cleaner signal.

---

**Stage 2 - Repeated hollowing of `aspnet_compiler.exe` (watchdog loop)**

The loaded PowerShell (`pid=7340`) then enters a watchdog loop, repeatedly spawning `aspnet_compiler.exe` as a sacrificial LOLBin and hollowing each instance with the SnakeKeylogger payload:

```
[09:49:16.392] PROC_CREATE | img=Aspnet_compiler.exe pid=2136 pimg=powershell.exe ppid=7340
[09:49:16.392] HANDLE_OPEN | src=powershell.exe spid=7340 tgt=Aspnet_compiler.exe tpid=2136
                             access=VM_WRITE|VM_OPERATION|CREATE_THREAD raw=0x001FFFFF type=write

[ALERT] Remote Injection | src=powershell.exe(7340) dst=Aspnet_compiler.exe(2136)
         technique=PROCESS_HOLLOWING confidence=HIGH score=90
[09:49:16.400] WRITE | src=powershell.exe spid=7340 dst=Aspnet_compiler.exe dpid=2136
                       addr=0000000000E20000 size=4544
```

This pattern repeats every ~4 seconds as the watchdog respawns crashed/deleted instances:

```
[ALERT] ... dst=Aspnet_compiler.exe(3740)  score=90
[ALERT] ... dst=Aspnet_compiler.exe(7600)  score=90
[ALERT] ... dst=Aspnet_compiler.exe(5348)  score=90
[ALERT] ... dst=Aspnet_compiler.exe(6028)  score=90
[ALERT] ... dst=Aspnet_compiler.exe(7372)  score=130  
[ALERT] ... dst=Aspnet_compiler.exe(7812)  score=130
[ALERT] ... dst=Aspnet_compiler.exe(2180)  score=130
[ALERT] ... dst=Aspnet_compiler.exe(1696)  score=130
[ALERT] ... dst=Aspnet_compiler.exe(280)   score=130
...
```

The sensor detected **every single hollowing attempt** across the entire watchdog loop - over 25 alerts in ~2 minutes.

**Why score varies (90 vs 130):** The initial batch of `aspnet_compiler.exe` instances (PIDs 2136, 3740, 7600, 5348, 6028) are spawned in a rapid burst within ~6ms. During this burst, multiple handle-open events stack up per target before write events arrive, pushing the score to 90 on handle activity alone. Later instances (PIDs 7372, 7812, 2180, etc.) are spawned one at a time by the watchdog loop (~4s apart), so the full event sequence - handle, write, parent-write-child boost, thread - plays out in order, reaching 130.

---

### Full PE section writes visible

For successfully hollowed instances, the sensor captures the PE section-by-section write pattern characteristic of process hollowing:

```
WRITE | spid=7340 dpid=5516 addr=0000000000400000 size=512       ← PE header
WRITE | spid=7340 dpid=5516 addr=0000000000402000 size=128000    ← .text section
WRITE | spid=7340 dpid=5516 addr=0000000000422000 size=4608      ← .rsrc / .reloc
WRITE | spid=7340 dpid=5516 addr=0000000000424000 size=512       ← remaining sections
```

The base address `0x400000` is the default ImageBase for 32-bit .NET executables, consistent with hollowing a .NET binary into the 32-bit `aspnet_compiler.exe` host.

---

## Detection in Action: Unidentified Dropper (Explorer.exe Injection)

The sensor was validated against a second real-world sample - a packed native 64-bit dropper (SHA256: `1c79d02819eade0c7cbc746a9667a5fdbf7bc773f264bb05a7832417ce67408c`) tagged by Triage sandbox as likely malicious, exhibiting Volume Shadow Copy deletion, Task Scheduler persistence, and process injection into `explorer.exe`.

### What the sensor saw

The dropper spawns, opens two handles to `explorer.exe` - first a broad handle with write, VM operation, and thread creation rights, then a second narrow handle requesting only thread creation - and creates a remote thread in a 4KB private executable region inside Explorer, all within ~10ms of process creation:

```
[12:16:44.165] PROC_CREATE  | img=sample.exe pid=3180 pimg=UNKNOWN ppid=4456
                               cmd="C:\Users\MrLowIQ\Desktop\sample.exe"
[12:16:44.175] HANDLE_OPEN  | src=sample.exe spid=3180 tgt=explorer.exe tpid=4456
                               access=VM_WRITE|VM_OPERATION|CREATE_THREAD raw=0x0000143A type=write
[12:16:44.175] HANDLE_OPEN  | src=sample.exe spid=3180 tgt=explorer.exe tpid=4456
                               access=CREATE_THREAD raw=0x00001402 type=thread
[ENRICH_DEBUG] pid=4456 inferredSrc=3180 type=131072 prot=32
[MEM][PRIVATE_EXEC] SRC=3180 DST=4456 START=0000000003220000 BASE=0000000003220000 SIZE=4096 TYPE=MEM_PRIVATE PROTECT=RX

[ALERT] Remote Injection | src=sample.exe(3180) dst=explorer.exe(4456)
        technique=SHELLCODE_REMOTE_THREAD confidence=HIGH score=90
```

The alert fired consistently across 5 detonations in the same session, each injecting into a different `explorer.exe` desktop instance. The shellcode stub was always a 4KB `MEM_PRIVATE + RX` region, though the exact address varied between runs.

Source attribution is inferred via handle correlation: the EDR identifies the most recent process that acquired `CREATE_THREAD` access to the target within a 5-second window, not from a direct kernel-level thread creation event.

ENRICH_DEBUG confirms the thread created in Explorer (pid=4456) was attributed to sample.exe (inferredSrc=3180) via recent handle correlation, with type=131072 (`MEM_PRIVATE`) confirming the private memory region.

### Scoring breakdown

| Signal | Score | Notes |
|--------|-------|-------|
| Cross-process handle with dangerous access mask | +20 | First handle: `0x143A` (VM_WRITE\|VM_OPERATION\|CREATE_THREAD) |
| Second handle open to same target | +20 | Second handle: `0x1402` (CREATE_THREAD only) - dedup issue, counted separately |
| Remote thread in `MEM_PRIVATE + RX` memory | +50 | 4KB shellcode stub |
| **Total** | **90** | Above alert threshold of 80 |

### Timing race condition - hook DLL vs malware

On some runs the hook DLL injection into the malware process failed (`[INJECT FAIL]`) - the dropper executed and injected into Explorer before the hook DLL could initialize. No WRITE event was captured and no alert fired. On successful runs the handle→thread sequence was captured, triggering the alert at score=90.

This is a known architectural limitation - see [Limitations](#limitations--known-issues).

### Possible direct syscall bypass - no write telemetry

Despite Triage sandbox confirming WriteProcessMemory into Explorer, no WRITE event was ever captured by the EDR across repeated runs. The exact bypass mechanism was not confirmed during analysis - possible explanations include direct syscalls, indirect syscalls, or use of an alternative API such as NtMapViewOfSection that bypasses the hook entirely. This is consistent with the sample's broader evasion profile.

### Deduplication gap

With proper handle event deduplication (one score bump per src→dst pair per window), the score would be 70 - below the alert threshold - since:

- Handle open (dedupped) → +20
- Remote thread in MEM_PRIVATE → +50

The alert currently fires only because duplicate handle events inflate the score to 90.

Note that this scoring gap exists specifically because write telemetry is absent - either due to evasion or hook timing. If the VirtualProtectEx hook were stable and re-enabled, a protect flip to executable would contribute +25, pushing the dedupped score to 95. Similarly, if NtMapViewOfSection were hooked, section-mapping as an alternative write primitive would also be visible (if used). Both are on the future work list but ultimately symptoms of the same root limitation: without ETW-TI, all write/protect visibility depends on userland hooks that can be bypassed or lost to timing races. ETW-TI would provide kernel-level write telemetry immune to both bypass vectors, making the dedup gap a non-issue.

---

## Components

| Component | Language | Key Files | Description |
|-----------|----------|-----------|-------------|
| **Kernel Driver** | C (WDM) | `driver.c`, `callbacks.c`, `events.c`, `utils.c`, `process_table.c` | Registers kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`) to collect process, thread, image load, and handle events. Stores events in a ring buffer and exposes them to userland via `IRP_MJ_READ`. Also accepts write/protect/resume events from the hook DLL via IOCTL. |
| **Userland Client** (`EDRClient.exe`) | C++ | `EDRClient.cpp`, `detections.cpp`, `output.cpp`, `parser.cpp` | Reads events from the kernel ring buffer, maintains a process table (PID, parent, image path, command line, privileges), enriches thread events with `VirtualQueryEx` (memory region type/protection), and runs the score-based behavioral detection engine. Injects the hook DLL into new processes. |
| **Hook DLL** | C++ | `inline_hook.cpp`, `dllmain.cpp` | Injected into target processes by the client via CreateRemoteThread + LoadLibraryW. Uses Zydis disassembler to place inline hooks on `NtWriteVirtualMemory`, `VirtualProtectEx`, and `NtResumeThread`. Hooked calls are forwarded to the kernel driver via IOCTL so the client can see cross-process memory writes, protection changes, and thread resumes that kernel callbacks alone can't observe. |

---

## Limitations & Known Issues

- **Lab only** - unsigned driver requires test-signing mode; no tamper protection
- **No ETW** - relies entirely on kernel callbacks + inline hooks; no script-block or AMSI integration
- **No disk/registry monitoring** - only detects in-memory injection, not persistence or file drops
- **Allowlisting is basic** - currently matches process names only (e.g. `svchost.exe`, `explorer.exe`, `WerFault.exe`). A production sensor/future work would validate full image paths and code-signing certificates to prevent allowlist bypass via name spoofing.
- **Hook DLL injection uses CreateRemoteThread** - a well-known injection vector that is easily detectable by other security tools and evadable by malware
- **Single-host** - no central logging, no network telemetry
- **WerFault noise** - crashed hollowed processes trigger WerFault handle opens that appear in telemetry
- **Handle event deduplication** - `ObRegisterCallbacks` fires multiple times per logical action (process creation, DLL load, etc.); the scoring engine currently counts each one, which inflates scores for parent-child pairs. A production version would deduplicate by (src, dst) within a short window.
- **VirtualProtect hooks disabled** - hooks for `NtProtectVirtualMemory` / `VirtualProtectEx` are currently commented out due to instability. Inline hooking caused crashes in multiple injected processes (likely due to incomplete RIP-relative relocation handling). These require further fixes before being re-enabled.
 
---

## What I Learned Building This

This project forced me to understand:

- How Windows kernel callbacks actually work (PsSetCreateProcessNotifyRoutineEx, ObRegisterCallbacks, etc.)
- The mechanics of process hollowing at the API level - `CreateProcess(SUSPENDED)` → `NtWriteVirtualMemory` → `NtResumeThread`
- Why EDR products hook ntdll (or use ETW-TI) - kernel callbacks alone can't see memory writes or protection changes
- How to build an inline hook using a disassembly engine (Zydis) to calculate safe patch lengths
- The difference between `MEM_PRIVATE`, `MEM_IMAGE`, and `MEM_MAPPED` in `VirtualQueryEx` and why it matters for injection classification
- How real EDR detection engines use behavioral correlation and scoring rather than simple signature matching

---

## Future Work

- ETW provider integration (Microsoft-Windows-Threat-Intelligence for write/protect visibility - requires PPL/ELAM or a bypass to subscribe)
- Script-block logging correlation
- Network telemetry (outbound connections from injected processes)
- YARA scanning of written memory regions
- Central logging (forward events to Sentinel)
- Broader technique coverage (APC injection, module stomping, transacted hollowing)
