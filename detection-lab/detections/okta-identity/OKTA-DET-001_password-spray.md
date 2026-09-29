---
title: Password Spray - Failed Logon Burst Across Multiple Accounts (Okta System Log)
status: lab prototype
mitre:
  - T1110.003: Brute Force - Password Spraying
source:
  - Okta System Log:
    - user.session.start: Failed authentication (invalid credentials)
    - user.session.start / user.authentication.auth_via_mfa: Successful authentication (correlation)
last_updated: 2026-09-28
severity: medium
confidence: medium
attack_simulation: Browser-based spray over Proton VPN (Serbian exit node) against 3 targets (alice, bob, carol), 3 rounds of guesses, bob's real password correct on round 3
notes: SuccessUsers non-empty elevates severity to High. minUsers threshold (3) is intentionally low for a 5-user lab tenant; Microsoft's built-in Okta analytic rule template requires more than 15 distinct users within a 5-minute window and would not have fired on this simulation.
---

## Summary

Detects password spray attempts by identifying bursts of failed logons from a single source IP across multiple distinct Okta accounts in a short time window. Aggregates `user.session.start` failures by source IP, then correlates against successful logons from the same IP to determine whether the spray worked.

## Why this matters

Password spraying tries one or a few passwords against many accounts to stay under per-account lockout thresholds, and it requires nothing more than a username list. Individual account-level monitoring misses it entirely - detection has to aggregate failures by source IP across accounts, the same shape-based approach as [`AD-DET-001`](../ad-identity/AD-DET-001_password-spray.md).

Microsoft's built-in Okta spray template requires more than 15 distinct users failing from one IP within a 5-minute bin before it fires - fine for a large tenant, but it means a small or early-stage spray generates zero alerts. In this lab, a 3-user spray recovered a valid password on the third round and would have gone undetected by the default template. Matching the threshold to tenant size is the whole reason for a custom rule here.

## Signal logic

**Failures vs. successes.** Failures come from `user.session.start` with `EventOriginalResultDetails == "INVALID_CREDENTIALS"`. Successes are read from both `user.session.start` and `user.authentication.auth_via_mfa`: a `user.session.start` success covers accounts with no MFA enrolled, and `auth_via_mfa` covers MFA-protected accounts too, since in this tenant a correct password alone already logs as a successful `auth_via_mfa`, before any second factor (see [`OKTA-DET-002`](OKTA-DET-002_mfa-fatigue.md), tuning note 10). A High result therefore means a valid password was found, not necessarily that MFA was passed.

**DistinctUsers, not FailCount.** Spray means few attempts against many accounts, the opposite shape of brute force. `array_length(FailedUsers)` measures that directly; a raw failure count would flag one mistyped password as loudly as a real spray.

**Time-bounded success correlation.** A success counts if it comes from the same `SrcIpAddr` and matches one of two cases. The first case is a username already in `FailedUsers` logging in between the spray start and `LastFail + successWindow` (15 minutes). The upper bound stops an unrelated later login from a shared IP (NAT, a reused VPN exit node) from falsely marking the spray as successful. The second case is any account logging in during the burst itself (±1 minute), so an account whose password was right on the first try, and that never failed, isn't missed. This is the same fix as `AD-DET-001`.

**Geo enrichment.** `Country`/`City` come from `geo_info_from_ip_address()` on `SrcIpAddr` - Okta has no domain-equivalent field, so this is the fastest triage signal available. Confirmed in this lab resolving a known VPN exit IP to Serbia/Belgrade.

**Severity.** `High` when `SuccessUsers` is non-empty (a working password was found), `Medium` otherwise.

**Only INVALID_CREDENTIALS, on purpose.** Microsoft's template also counts `VERIFICATION_ERROR` failures. That result can also come from failed MFA verification, so including it risks pulling push-bombing victims (see [`OKTA-DET-002`](OKTA-DET-002_mfa-fatigue.md)) into `FailedUsers` when both attacks come from the same IP. Left out here to keep this rule about wrong passwords only.

False positives: shared corporate egress IPs where several employees mistype passwords close together, or vulnerability scanners hitting multiple accounts. Raise `minUsers` above 3 for larger tenants, and allowlist known corporate NAT ranges or scanning infrastructure.

## KQL

```kusto
// Detection: Password Spray - Failed Logon Burst (Okta)
// Event types: user.session.start (Failure/INVALID_CREDENTIALS),
//              user.session.start + user.authentication.auth_via_mfa (Success, correlation)
// MITRE:       T1110.003 - Brute Force: Password Spraying
// Source:      OktaV2_CL (Okta System Log via Sentinel Okta Single Sign-On CCF connector)
// Lab:         Telemetry confirmed in Sentinel workspace law-1, Okta Integrator Free tenant
//
// TUNING NOTES:
// 1. minUsers = 3 is low for this 5-user lab. Raise to match real tenant
//    size - Microsoft's own template needs more than 15, too high to catch an
//    early-stage or quiet spray.
// 2. lookback = 24h - tighten for fast/noisy sprays, widen for slow ones.
//    Uses a rolling lookback rather than fixed bins, so a spray isn't
//    split across a bin boundary.
// 3. Add known scanner/NAT/proxy IPs to an exclusion list:
//    | where SrcIpAddr !in (known_shared_ips)
// 4. Severity = High (a working password was found) should trigger
//    escalation.
// 5. geo_info_from_ip_address() can return nulls for some VPN/hosting
//    ranges. Treat empty Country/City as unresolved, not safe.
// 6. Only INVALID_CREDENTIALS is counted as a failure. Microsoft's template
//    also includes VERIFICATION_ERROR, which can come from failed MFA and
//    would mix MFA-fatigue victims into the spray. Add it only if you've
//    confirmed what produces it in your tenant.
// 7. successWindow = 15m after the last failure. An attacker who finds a
//    working password usually logs in right away. Widen it if you expect
//    them to come back later with it, but that raises the odds of a
//    legitimate login from a shared IP counting as a hit.
// 8. Any success from the spray IP within ±1m of the burst counts, even
//    for accounts that never failed. On a shared IP, a legitimate login
//    that happens to land during the spray would count too.
//
let lookback = 24h;
let minUsers = 3;
let successWindow = 15m;
let events = OktaV2_CL
| where TimeGenerated > ago(lookback)
| where EventOriginalType in ("user.session.start", "user.authentication.auth_via_mfa")
| where isnotempty(SrcIpAddr);
// --- Failed logons: password rejected ---
let spray = events
| where EventOriginalType == "user.session.start"
| where EventResult == "Failure" and EventOriginalResultDetails == "INVALID_CREDENTIALS"
| summarize FirstFail = min(TimeGenerated), LastFail = max(TimeGenerated), FailCount = count(), FailedUsers = make_set(ActorUsername, 100) by SrcIpAddr
| where array_length(FailedUsers) >= minUsers;
// --- Successful logons from the same source: targeted accounts within the window, or any account during the burst ---
let hits = events
| where EventResult == "Success"
| join kind=inner (spray | project SrcIpAddr, FirstFail, LastFail, FailedUsers) on SrcIpAddr
| where TimeGenerated between ((FirstFail - 1m) .. (LastFail + successWindow))
| where set_has_element(FailedUsers, ActorUsername)
    or TimeGenerated between ((FirstFail - 1m) .. (LastFail + 1m))
| summarize SuccessUsers = make_set(ActorUsername, 100), FirstSuccess = min(TimeGenerated) by SrcIpAddr;
// --- Combine, enrich, score ---
spray
| join kind=leftouter hits on SrcIpAddr
| extend Severity = iff(array_length(SuccessUsers) > 0, "High", "Medium")
| extend GeoInfo = geo_info_from_ip_address(SrcIpAddr)
| extend Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city)
| project SrcIpAddr, Country, City, FirstFail, LastFail, FailCount, DistinctUsers = array_length(FailedUsers), FailedUsers, SuccessUsers, FirstSuccess, Severity
```
