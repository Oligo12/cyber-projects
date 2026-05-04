# Evidence: detection of Explorer injector sample

**Sample.** A Windows EXE that bypasses Microsoft Defender at time of testing. Opens a handle into `explorer.exe`, plants a small (4 KB) shellcode region in explorer's address space, and creates a thread inside explorer pointing at the planted region.

**Defender verdict at time of test:** clean (no detection).
**This EDR's verdict:** `SHELLCODE_REMOTE_THREAD` alert at score 80, HIGH confidence.

---

## Log excerpt

From a clean run, post-cleanup, post-trust-gate:

```
[14:09:25.586] THREAD_CREATE | img=unknownsample.exe pid=1292 tid=3712 start=00007FFEBB842B20 base=00007FFEBB842000 size=831488 type=MEM_IMAGE prot=RX
[MEM][IMAGE_EXEC] SRC=528 DST=1292 START=00007FFEBB842B20 BASE=00007FFEBB842000 SIZE=831488 TYPE=MEM_IMAGE PROTECT=RX
[14:09:25.586] THREAD_CREATE | img=unknownsample.exe pid=1292 tid=7340 start=00007FFEBB842B20 base=00007FFEBB842000 size=831488 type=MEM_IMAGE prot=RX
[14:09:25.590] HANDLE_OPEN  | src=unknownsample.exe spid=1292 tgt=explorer.exe tpid=4456 access=VM_WRITE|VM_OPERATION|CREATE_THREAD raw=0x0000143A type=write
[14:09:25.590] HANDLE_OPEN  | src=unknownsample.exe spid=1292 tgt=explorer.exe tpid=4456 access=CREATE_THREAD raw=0x00001402 type=thread
[SCORE] tiny private-exec region bonus: src=1292 dst=4456 size=4096
[ALERT] Remote Injection | src=unknownsample.exe(1292) dst=explorer.exe(4456) technique=SHELLCODE_REMOTE_THREAD confidence=HIGH score=80
[MEM][PRIVATE_EXEC] SRC=1292 DST=4456 START=0000000003220000 BASE=0000000003220000 SIZE=4096 TYPE=MEM_PRIVATE PROTECT=RX
[14:09:25.590] THREAD_CREATE | img=explorer.exe pid=4456 tid=5856 start=0000000003220000 base=0000000003220000 size=4096 type=MEM_PRIVATE prot=RX
```

---

## What happened, in chain-detection terms

1. **`unknownsample.exe(1292)` opens a handle into `explorer.exe(4456)`** with `VM_WRITE | VM_OPERATION | CREATE_THREAD` access mask.
   Score: **+20** (handle primitive)

2. **The sample plants a 4 KB private executable region** in explorer's address space at `0x3220000`. Tiny private-exec region triggers the shellcode-region bonus.
   Score: **+10** (tiny region)

3. **A new thread is created inside `explorer.exe`** pointing at the planted region — the start address (`0x3220000`) matches the recently-allocated private-exec region.
   Score: **+50** (thread create on private-exec region)

**Total chain score: 80.** ALERT threshold met.
**Technique:** `SHELLCODE_REMOTE_THREAD` (private executable destination, not image-backed).

> Note on log ordering: the `THREAD_CREATE` line for the explorer thread appears after the `[ALERT]` line in the excerpt above. That's a logging quirk — the thread event is what scored +50 and triggered the alert, but the human-readable `THREAD_CREATE` log line and the `[ALERT]` line come from different code paths and interleave in the output. The alert math is `20 + 10 + 50 = 80`, with the +50 sourced from this exact thread event.


---

## Why the trust subsystem did not bypass this

The source process lives under `C:\Users\<user>\Desktop\`, which is not a trusted system directory. Layer 2 of the trust gate (trusted-directory prefix check) fails immediately, so the signature check never even runs.

For the inverse — chains with the same primitive pattern that *are* suppressed because the source IS a trusted system binary — see [`trust-bypass.md`](trust-bypass.md).

---

## Reproducibility

Three out of three runs that completed the injection without crashing produced this alert. The sample is unstable; some detonations crash via WerFault before completing the injection. On the runs that succeed, the EDR detects them every time.
