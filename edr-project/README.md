# EDR Project — Process Injection Detection (v1)

A custom Windows endpoint detection prototype (the "D" of EDR), built from scratch in C/C++, focused on detecting in-memory process injection across user-mode and kernel telemetry sources. Response automation is out of scope for v1 — see `KNOWN_LIMITATIONS.md`.

**Version status:** v1 complete. Validated against real malware samples that bypass Microsoft Defender at time of testing.

---

**Author:** Nikola Marković  
**Project status:** ongoing                                                                                                                              
**Last updated:** 2026-05-04          
**Repo:** https://github.com/Oligo12/cyber-projects/                                                                   
**Email:** nikola.z.markovic@pm.me                                                                                                 
**LinkedIn:** https://www.linkedin.com/in/nikolazmarkovic/  

---

## Headline results

| Test                                                              | Outcome                                                |
|-------------------------------------------------------------------|--------------------------------------------------------|
| Unidentified Explorer.exe injector (Defender-evasive)    | Detected as `SHELLCODE_REMOTE_THREAD` on every successful detonation |
| SnakeKeylogger PowerShell variant (17 injection chains across 3 detonations) | Every chain detected as `PROCESS_HOLLOWING`, despite source being signed-Microsoft PowerShell in System32 |
| MusNotification.exe + taskhostw.exe (legitimate Windows behavior with injection-like primitives) | 10 chains suppressed via trust subsystem; zero false-positive alerts |
| AgentTesla (32-bit malware)                                       | Limitation: kernel callbacks observe it, but the user-mode hook DLL is x64-only — chain doesn't accumulate enough score. Documented in `KNOWN_LIMITATIONS.md`. |

See the `evidence/` folder for excerpts of the actual log lines.

---

## Architecture, in one paragraph

A test-signed kernel driver registers four standard Windows callbacks (process / thread / image / handle) and emits structured events into a 16384-slot ring buffer. A user-mode client drains the ring buffer over an IRP-based device interface, tracks injection chains keyed on `(source PID, destination PID, source createTime, destination createTime)` to defeat PID recycling, and runs rules-based scoring against observed primitives. A user-mode hook DLL is injected into every running process to capture three Nt-layer syscalls (`NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtResumeThread`) — the events kernel callbacks alone can't see. A layered trust subsystem (path → trusted-directory → LOLBin denylist → Authenticode signature with embedded + catalog support) suppresses alerts on legitimate signed-Microsoft system processes without weakening detection of malware that abuses LOLBins like PowerShell.

For the full technical writeup, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## What it detects

| Technique                          | MITRE ID    | Example sample             |
|------------------------------------|-------------|----------------------------|
| Process Hollowing                  | T1055.012   | SnakeKeylogger             |
| Shellcode Remote Thread            | T1055       | Defender-evasive injector  |
| Image-Based Injection              | T1055       | —                          |

For full detection writeups including the chain logic and validating samples, see [`DETECTIONS.md`](DETECTIONS.md).

---

## Repo layout

```
edr-project/
├── README.md                ← you are here
├── ARCHITECTURE.md          ← full technical writeup
├── DETECTIONS.md            ← what gets detected and how
├── KNOWN_LIMITATIONS.md     ← scope boundaries + v2 backlog
├── evidence/                ← log excerpts demonstrating real detections
│   ├── explorer-injector-alert.md
│   ├── snake-alerts.md
│   └── trust-bypass.md
└── src/
    ├── kernel/              ← driver source (driver.c, callbacks.c, events.c, ...)
    └── usermode/
        ├── dll/             ← inline-trampoline hook DLL
        └── client/          ← orchestrator + detection engine
```

---

## Tech stack

- **Kernel driver:** WDM, Visual Studio + WDK, four standard callback types (`PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`)
- **User-mode client:** C++ (Visual Studio), C++14, talks to driver via `DeviceIoControl` and `ReadFile` over `\\.\MyEDR`
- **Hook DLL:** C++, x64, inline trampoline hooks on three Nt-layer syscalls; loaded into target processes via `CreateRemoteThread(LoadLibrary)`
- **Authenticode verification:** WinTrust + WinCrypt for both embedded (`WINTRUST_FILE_INFO`) and catalog signatures (`CryptCATAdmin*` + `WINTRUST_CATALOG_INFO`), with SHA-256 → SHA-1 algorithm fallback for legacy catalogs

---

## Setup & Build

### Requirements
- Visual Studio 2022 + Windows Driver Kit (WDK)
- Test VM with test-signing enabled (`bcdedit /set testsigning on`)
- [Zydis](https://github.com/zyantific/zydis) disassembler — used by the hook DLL for instruction-length decoding when calculating patch length

### Expected install layout
The userland client and hook DLL look for a fixed path:
- `C:\drivers\EDRHookClean.dll` — hook DLL injected into target processes
- `C:\drivers\edr_log.txt` — runtime log output

These paths are currently hardcoded in source (see refactoring backlog in `KNOWN_LIMITATIONS.md`). Change at build time if needed.

### Build & run
1. Build kernel driver (`MyEDR.sys`) and userland (`EDRClient.exe` + `EDRHookClean.dll`) for x64
2. Copy all three into `C:\drivers\` on the test VM
3. Load the driver: `sc create MyEDR type= kernel binPath= C:\drivers\MyEDR.sys` then `sc start MyEDR`
4. Run `EDRClient.exe` as Administrator

### Note on the skip list
`main.cpp` and `output.cpp` both skip-list `OSRLOADER.exe` and `Dbgview.exe` — these are kernel-debug tools used during development and have no effect outside that environment. They'll be removed when the skip list is refactored (see backlog).

---

## Notes on this project

This is a defensive monitoring tool. The hooking techniques used for telemetry are well-documented in Microsoft Detours and across public references; they are a standard approach used by many EDR-style tools for user-mode coverage when ETW Threat-Intelligence is not available (which requires PPL-AntiMalware code-signing, granted to formal AV vendors only).

### Development context

Developed solo over approximately two months as a learning exercise and portfolio piece, with AI-assisted iteration (Claude). Architectural decisions, malware sample selection, validation methodology, and design tradeoffs (e.g., the layered trust subsystem, the scope decision to add catalog signature support, the choice to hook at the Nt-layer rather than Win32) were driven by me; implementation was iterative collaboration. Each detection layer was empirically validated against real malware samples before moving to the next.

This project is the v1 of an ongoing effort to build hands-on understanding of Windows internals, EDR mechanics, and malware behavior.

---

## Author

**Nikola Marković**
- Email: nikola.z.markovic@pm.me
- LinkedIn: https://www.linkedin.com/in/nikolazmarkovic/
- Repo home: https://github.com/Oligo12/cyber-projects/

---

## License

This repository is released under the [Unlicense](../LICENSE) (public domain).
