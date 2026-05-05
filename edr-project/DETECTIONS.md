# Detections

This document lists what the EDR detects, mapped to MITRE ATT&CK where applicable. For *how* it detects them, see [`ARCHITECTURE.md`](ARCHITECTURE.md). For what it doesn't catch yet, see [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).

---

## Coverage summary

| Technique                          | MITRE ID    | Detection name in logs       | Confidence |
|------------------------------------|-------------|-------------------------------|------------|
| Process Hollowing                  | T1055.012   | `PROCESS_HOLLOWING`           | HIGH       |
| Shellcode Remote Thread            | T1055       | `SHELLCODE_REMOTE_THREAD`     | HIGH       |
| Image-Based Injection              | T1055       | `IMAGE_BASED_INJECTION`       | HIGH       |

All three fire as `[ALERT] Remote Injection | … technique=<name> confidence=HIGH score=<N>` once the chain crosses the score-80 threshold (see `ARCHITECTURE.md` §4 for scoring model).

A second log severity, `[SUSPICIOUS]`, fires at score-60 to leave a forensic trail when execution is missed (direct syscalls, hook bypass, race conditions). One SUSPICIOUS line per chain — not per primitive event.

A third log line, `[TRUST_BYPASS]`, records when a chain that *would* have alerted was suppressed by the trust subsystem because the source was a signed system binary. This is intentional: silent suppression is bad practice; recording the suppression keeps the audit trail.

---

## T1055.012 — Process Hollowing

**Pattern observed.** A parent process creates a child in a suspended state, opens a handle into the child with write/operation/create-thread access, writes shellcode or a replacement image into the child's address space, and resumes the child's main thread to begin execution of the planted code.

**How it's detected.** Score accumulation across the chain:

- Handle to suspended child with dangerous access mask → `+20`
- Parent-to-child handle context bonus (parent → recently-created child) → `+10`
- Write into child's memory → `+30`
- Parent-to-child write bonus (the hollowing-specific signature) → `+50`
- `NtResumeThread` on the suspended target → `+50`

A clean hollowing chain reaches score 160. Threshold for `[ALERT]` is 80, so the alert fires reliably even with one or two missed primitives.

**Why this works.** The parent-child relationship matters. A normal `CreateProcess(CREATE_SUSPENDED)` followed by `ResumeThread` is part of the legitimate Windows process-launch path; what makes it hollowing is that the parent *writes into the child between create and resume.* That write is what flips the chain from "normal launch" to "PROCESS_HOLLOWING."

**Validated against:** SnakeKeylogger PowerShell variant injecting into `Aspnet_compiler.exe`. Each `Aspnet_compiler.exe` instance produces an independent alert.

---

## T1055 — Shellcode Remote Thread Injection

**Pattern observed.** A source process opens a handle into a target process (typically *not* its child), writes shellcode into the target's address space, optionally flips the protection of that region to PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ, then creates a thread inside the target whose start address points into the planted region.

**How it's detected.** Same primitives as hollowing, but a different *shape* of chain:

- Handle to non-child target with dangerous access mask → `+20`
- Write into target's memory → `+30`
- Protect to a private executable region (RW→RX, R→RX) → `+20`
- Tiny private-exec region bonus (≤ 0x1000) → `+10`
- Thread create where the start address falls in private-exec memory → `+50`
- (Bonus, not always present) `startMatchesWrite` — the thread's start address matches a region recently written to → adds confidence

Reaches alert threshold via the handle + write + thread path (60 → 80 with the protect/region bonus, or via private-exec thread alone).

**Why "tiny region" matters.** Legitimate code allocations are usually larger than a single page. Shellcode plants are commonly 200-800 bytes. A private executable region under 4KB is a strong shellcode signal even before correlating with anything else.

**Validated against:** Unidentified injection sample (unknownsample.exe) that bypasses Microsoft Defender at time of testing. Each detonation produces one alert at score 80, technique=SHELLCODE_REMOTE_THREAD.

---

## T1055 — Image-Based Injection

**Pattern observed.** A source process opens a handle into the target, allocates or maps a memory region, writes a complete PE image (DLL or EXE) into that region instead of raw shellcode, and creates a thread starting at the entry point of the mapped image.

**How it's detected.** The thread create event fires with `ThreadStartType` indicating an image-mapped region rather than private memory:

- Handle to target with dangerous access mask → `+20`
- Write into target's memory → `+30`
- Thread create where start address falls in an image-backed region → `+50`

The `IMAGE_BASED_INJECTION` technique label is selected when the thread starts in image-mapped memory, distinguishing it from shellcode in private memory.

**Why split this out.** Image-based injection looks innocuous on the surface — image-backed memory is where legitimate DLLs live too. The detection has to correlate "the source process *just wrote* into this image-backed region" with "now there's a new thread starting inside it." That correlation is what makes it suspicious; either signal alone is unremarkable.

---

## Severity ladder

```
score < 60      → no log
score 60-79     → [SUSPICIOUS] line, one per chain (after trust gate)
score >= 80     → [ALERT] line, one per chain (after trust gate)
trusted source  → [TRUST_BYPASS] line in place of alert
```

The trust gate runs at 60 and 80 boundaries (cheaply, via per-chain cache). It does not run on every event, so non-decision-point events stay in the kernel-callback / hook hot path with no signature-verification overhead.

---

## What's NOT detected

Listed for honesty:

- **DLL Sideloading (T1574.002)** — out of v1 scope. Needs filesystem-side telemetry (minifilter) to detect the abuse pattern (legitimate signed binary loading attacker-controlled DLL from a writable directory). Roadmap.
- **APC Injection (T1055.004)** — needs an `NtQueueApcThread` user-mode hook (or ETW-TI's APC events). Not implemented.
- **AtomBombing / Process Doppelgänging** — exotic injection variants relying on transactional NTFS / atom tables. Not in scope; v2+ if ever.
- **Manual mapping / reflective loading** with no module-mapping events — partial coverage today via private-RX scoring, but not validated against representative samples.
- **32-bit malware** — see `KNOWN_LIMITATIONS.md`. Kernel callbacks see them; user-mode write/protect telemetry doesn't (DLL is x64-only). AgentTesla detonates cleanly with kernel events visible, but typical hollowing chains don't accumulate enough score to alert.

See `KNOWN_LIMITATIONS.md` for the full inventory and v2 paths.
