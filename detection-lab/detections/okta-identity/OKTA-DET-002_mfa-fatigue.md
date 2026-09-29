---
title: MFA Fatigue - Repeated Push Prompts Followed by Approval (Okta System Log)
status: lab prototype
mitre:
  - T1621: Multi-Factor Authentication Request Generation
source:
  - Okta System Log: 
    - system.push.send_factor_verify_push: Push notification sent to a user's enrolled device
    - user.authentication.auth_via_mfa (Failure): Push denied / failed MFA attempt (context, observed in this lab)
    - user.mfa.okta_verify.deny_push: User denied a push prompt (context, not observed in this lab)
    - user.authentication.auth_via_mfa (Success): Successful MFA-backed authentication (correlation)
last_updated: 2026-09-28
severity: medium
confidence: medium
attack_simulation: Correct password for dave (Okta Verify enrolled), 6 push prompts spammed in quick succession, 5 denied, 6th approved
notes: Approved > 0 elevates severity to High. minPushes threshold (3) is intentionally low for a lab; tune to environment push-frequency baseline. Microsoft's built-in MFA Fatigue (OKTA) template requires more than 10 pushes and would not have fired on this 6-push simulation. Number-matching was deliberately left disabled in this Okta org to allow this simulation.
---

## Summary

Detects MFA fatigue (push bombing) attempts by identifying a burst of push notification prompts sent to a single user's enrolled device, then checking whether a successful MFA authentication followed. A high push count followed by an approval is the signature of an attacker spamming prompts until the victim taps "approve" out of annoyance or confusion.

## Why this matters

MFA fatigue targets the human, not the cryptography. Once an attacker has a valid password, push MFA without number matching becomes the weak link: they just retry the login until the victim taps "approve" out of habit or frustration. No bypass needed, just persistence - the same pattern behind real incidents like the 2022 Uber breach.

Number matching (entering an on-screen code into the app) mostly closes this gap, since a bystander can't approve blind. It's disabled in this lab org so the simulation could run; a production tenant should have it on, at which point this detection becomes a compensating control rather than a primary one.

Microsoft ships a built-in "MFA Fatigue (OKTA)" analytic rule, but it only fires on more than 10 pushes. The 6-push attack in this lab, which ended in an approval, would not have fired it. As with [`OKTA-DET-001`](OKTA-DET-001_password-spray.md), the point of the custom rule is a threshold that matches the environment.

## Signal logic

**Push burst by target user.** `system.push.send_factor_verify_push` events are grouped by `ActorUsername`, the push target, not the attacker. `PushCount >= minPushes` (3) flags a burst.

**Denials as context.** Failed `user.authentication.auth_via_mfa` events for the same user are counted into `Denied`. In this lab tenant, every rejected push was logged that way and `user.mfa.okta_verify.deny_push` never appeared, so it's kept only for tenants that do log it. `Denied` therefore counts failed MFA attempts in general - a wrong one-time code would land there too - but in this lab all 5 were the rejected pushes. Several denials followed by an approval is a much stronger fatigue signal than pushes alone, since it shows the user actively rejecting prompts they didn't expect before giving in.

**Approval correlation.** A push burst alone isn't proof of an attack. `Approved` counts `user.authentication.auth_via_mfa` successes between `FirstPush` and `LastPush + approvalWindow` (15 minutes), and `Severity` only escalates to `High` when that count is non-zero. The upper bound stops an unrelated legitimate login hours later from being counted as an approval. `ApprovalIps` lists the IPs those successes came from. In this lab the approval came from dave's phone, a different IP from the VPN requester.

**Source IP is the requester, not the victim.** The IP on a push-send event is the client that started the login which triggered the push - in an attack, that's the attacker's session, not the victim's phone. `SrcIpAddr` (one value, used for geo) and `SrcIps` (all distinct values, up to 10) are taken from the push events, so they point at whoever is generating the prompts. In this lab it resolved to the same VPN exit node used in the OKTA-DET-001 spray.

**No automatic spray correlation.** This query doesn't join against OKTA-DET-001 results. Because both rules surface the attacker's IP, matching them up is a quick manual pivot for now.

**Geo enrichment.** `Country`/`City` come from `geo_info_from_ip_address()` on `SrcIpAddr` - the fastest triage signal available here, since Okta has no domain-equivalent field to filter on. A push requested from a country the user has never logged in from is a strong escalation cue.

False positives: legitimate multi-app re-authentication storms, or Okta's own push retries on a poor connection. Raise `minPushes` in environments with heavy SSO usage, and exclude known shared or service accounts that generate frequent pushes.

## KQL

```kusto
// Detection: MFA Fatigue - Repeated Push Prompts Followed by Approval (Okta)
// Event types: system.push.send_factor_verify_push (push sent),
//              user.authentication.auth_via_mfa (Failure, push denied, context),
//              user.mfa.okta_verify.deny_push (push denied, context, not seen in this lab),
//              user.authentication.auth_via_mfa (Success, correlation)
// MITRE:       T1621 - Multi-Factor Authentication Request Generation
// Source:      OktaV2_CL (Okta System Log via Sentinel Okta Single Sign-On CCF connector)
// Lab:         Telemetry confirmed in Sentinel workspace law-1, Okta Integrator Free tenant
//
// TUNING NOTES:
// 1. minPushes = 3 is lab-tuned. Raise for heavy multi-app SSO, where
//    legitimate pushes cluster. Microsoft's template requires more than 10.
// 2. lookback = 24h. A real burst usually finishes in under a minute.
// 3. Approved > 0 (High) = a prompt was accepted mid-burst. Escalate.
//    Denied > 0 as well makes compromise near-certain.
// 4. No automatic link to OKTA-DET-001. Both surface the requesting IP,
//    so pivot manually.
// 5. geo_info_from_ip_address() can return nulls for VPN/hosting ranges.
//    Treat empty Country/City as unresolved, not safe.
// 6. Counts cover the whole 24h, not one burst. Microsoft's template
//    groups by Okta session ID (authenticationContext.externalSessionId),
//    but no equivalent column was found in OktaV2_CL, so counts here
//    are per user across the lookback.
// 7. approvalWindow = 15m after the last push. Widen for late approvers,
//    tighten to avoid overlap with normal logins.
// 8. SrcIpAddr is one sample IP for geo; SrcIps lists all. More than one
//    requesting IP in a burst is worth a look.
// 9. Denied = failed auth_via_mfa + deny_push. This tenant logged rejected
//    pushes only as auth_via_mfa failures. Wrong one-time codes also
//    count, so Denied means failed MFA attempts, not strictly denials.
// 10. A correct password also logs as auth_via_mfa Success here. If an
//     attacker re-enters it for every push, those land in the window and
//     count as Approved (false High). Not an issue in this lab. Before
//     escalating, compare ApprovalIps against SrcIps: a success from the
//     requesting IP is the password being re-entered, not the phone approving.
//
let lookback = 24h;
let minPushes = 3;
let approvalWindow = 15m;
// --- Push bursts and denials by target user ---
let pushes = OktaV2_CL
| where TimeGenerated > ago(lookback)
| where (EventOriginalType == "system.push.send_factor_verify_push" and EventResult == "Success")
    or (EventOriginalType == "user.authentication.auth_via_mfa" and EventResult == "Failure")
    or EventOriginalType == "user.mfa.okta_verify.deny_push"
| extend IsPush = EventOriginalType == "system.push.send_factor_verify_push"
| summarize FirstPush = minif(TimeGenerated, IsPush), LastPush = maxif(TimeGenerated, IsPush), PushCount = countif(IsPush), Denied = countif(not(IsPush)), SrcIpAddr = take_anyif(SrcIpAddr, IsPush), SrcIps = make_set_if(SrcIpAddr, IsPush, 10) by ActorUsername
| where PushCount >= minPushes;
// --- Successful MFA completions, for correlation ---
let success = OktaV2_CL
| where TimeGenerated > ago(lookback)
| where EventOriginalType == "user.authentication.auth_via_mfa"
| where EventResult == "Success"
| project ActorUsername, TimeGenerated, ApprovalIp = SrcIpAddr;
// --- Combine, enrich, score ---
// NOTE: the approval check happens inside summarize, not as a prior filter.
// Filtering rows with `where` before this aggregation would drop a user
// entirely if their only success events were earlier the same day (before
// FirstPush) - they'd disappear from the output instead of showing up with
// Approved = 0. Aggregating first avoids that false negative.
pushes
| join kind=leftouter (success) on ActorUsername
| summarize LastPush = max(LastPush), PushCount = max(PushCount), Denied = max(Denied), FirstPush = min(FirstPush), SrcIpAddr = take_any(SrcIpAddr), SrcIps = take_any(SrcIps), Approved = countif(TimeGenerated between (FirstPush .. LastPush + approvalWindow)), ApprovalIps = make_set_if(ApprovalIp, TimeGenerated between (FirstPush .. LastPush + approvalWindow), 10) by ActorUsername
| extend Severity = iff(Approved > 0, "High", "Medium")
| extend GeoInfo = geo_info_from_ip_address(SrcIpAddr)
| extend Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city)
| project ActorUsername, SrcIpAddr, SrcIps, Country, City, FirstPush, LastPush, PushCount, Denied, Approved, ApprovalIps, Severity
```
