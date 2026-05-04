# Evidence: trust subsystem suppressing legitimate Windows behavior

**Background.** `MusNotification.exe` (Microsoft Update Session Orchestrator notification component) and `taskhostw.exe` (generic Windows task host) both perform write+thread injection patterns into their child processes during normal operation. These chains score `>= 80` and **would generate `PROCESS_HOLLOWING` false-positive alerts without a trust subsystem.**

The trust subsystem suppresses them by verifying:

1. Source path is under `C:\Windows\System32\`
2. Source is not on the LOLBin denylist
3. Authenticode signature verifies (embedded for `taskhostw`, catalog-signed for `MusNotification` — both paths supported)

When all three layers pass, the chain is bypassed silently and a `[TRUST_BYPASS]` line is written for the audit trail.

---

## Log excerpt

One full session, 10 chains bypassed:

```
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(8784)  dst=MusNotifyIcon.exe(5908)  primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(1080)  dst=MusNotifyIcon.exe(5768)  primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(7160)  dst=MusNotifyIcon.exe(664)   primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(9536)  dst=MusNotifyIcon.exe(10576) primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(2144)  dst=MusNotifyIcon.exe(2136)  primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(4016)  dst=MusNotifyIcon.exe(1356)  primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(2552)  dst=MusNotifyIcon.exe(2640)  primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(9052)  dst=MusNotifyIcon.exe(9632)  primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=MusNotification.exe(2680)  dst=MusNotifyIcon.exe(9460)  primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
[TRUST_BYPASS] suppressed alert | src=taskhostw.exe(5172)        dst=explorer.exe(4448)       primitives=handle:1,write:1,protect:0,thread:1,resume:0 score=130 (source verified as signed system binary)
```

---

## What this excerpt shows

- **10 distinct chains, each scoring 130, all suppressed.**
- Without the trust subsystem these would have produced 10 false-positive `PROCESS_HOLLOWING` alerts in a single session.
- Each chain shows `handle:1, write:1, thread:1` — **the exact primitive pattern that real malware also produces.** The difference between FP and TP here is NOT the behavior; it's the identity and trust posture of the source binary.
- The trust gate decision per binary happens once per session (`g_TrustCache` hit thereafter). Nine of the bypasses above came from different `MusNotification.exe` instances — same binary, different PIDs — so the actual `WinVerifyTrust` call ran exactly once.

---

## Notable: catalog-signing path matters

`MusNotification.exe` is **catalog-signed**, not embedded-signed. The trust subsystem's catalog signature support (with SHA-256 → SHA-1 fallback for legacy catalogs) is what makes this bypass possible. Earlier iterations using embedded-signature-only verification failed on this exact binary, producing the same alerts as malware would.

---

## Validating this evidence

Compare against a malicious chain with similar primitives in [`explorer-injector-alert.md`](explorer-injector-alert.md) — same primitive pattern, opposite verdict, because the source path differs.
