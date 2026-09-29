---
title: Policy Tampering Shortly After Admin Grant (Okta System Log)
status: lab prototype
mitre:
  - T1556.009: Modify Authentication Process - Conditional Access Policies
source:
  - Okta System Log:
    - policy.lifecycle.create / update / delete / deactivate: Policy lifecycle change
    - policy.rule.create / update / delete / deactivate: Policy rule change
    - user.account.privilege.grant: Admin role granted to a user account (correlation)
last_updated: 2026-09-28
severity: medium
confidence: medium
attack_simulation: eve (freshly granted Super Organization Administrator) created then deleted a throwaway OKTA_SIGN_ON policy "Lab-Temp", ~2 and ~4 minutes after her own admin grant
notes: Severity elevates to High only when the actor became admin within recentAdminWindow (30m) before the policy change; unrelated policy edits by established admins stay Medium. policy.rule.* events are in scope but were not simulated in this lab.
---

## Summary

Detects policy and policy rule changes (create, update, delete, deactivate) and escalates to High when the account making the change was granted admin rights shortly beforehand. Changes by established admins still surface, at Medium. Reuses the same `user.account.privilege.grant` signal as [`OKTA-DET-003`](OKTA-DET-003_new-admin.md) to catch the specific chain of "just became admin, immediately touched a policy." 

## Why this matters

Okta policies are the authentication guardrails - MFA requirements, allowed networks, session lifetimes, password rules. An attacker who's just escalated to admin can weaken or disable one of these to open a persistent foothold that survives well past the original compromised credential being rotated. Deleting or reverting the change afterwards hides it from anyone looking at the Admin Console, though the System Log still records both steps - which is exactly what this rule relies on.

Most of the actual weakening happens at the rule level, not the policy level. Dropping an MFA requirement or widening an allowed network zone is an edit to a policy rule, which Okta logs as `policy.rule.update`, not `policy.lifecycle.update`. A rule that only watched `policy.lifecycle` would miss the most likely form of this attack.

Microsoft's closest built-in template, "New Device/Location sign-in along with critical operation," correlates risky operations - including both `policy.lifecycle` and `policy.rule` events - with a login flagged as a new country, new geolocation, and new device, all three at once, within the same hour. It's a good rule, but it depends on the attacker's session looking unfamiliar. In this lab, eve's session never met that condition. Her policy tampering came from the same VPN exit IP used for the earlier spray and push-bombing steps, and her first login, right after the grant, had no sign-in history for Okta to compare against: New Device, New Geo-Location and New Country were all logged as UNKNOWN rather than flagged, and every later event in her session came back NEGATIVE. An account with no prior sign-in history gave that template nothing to fire on. This detection doesn't check device or location at all; it fires purely on the timing between the grant and the policy change, so it catches a chain like eve's even when Okta has nothing to call "new".

## Signal logic

**Correlates against the same admin-grant event as OKTA-DET-003.** `recentAdmins` pulls `user.account.privilege.grant` events and extracts the new admin by target type (`User`), falling back to `OriginalTarget[0]`, the position observed in this lab, if the typed lookup comes back empty. Policy events are then left-joined to it on `ActorUsername == NewAdmin`.

**Lifecycle and rule events are both in scope.** `tamperEvents` covers create, update, delete, and deactivate for both policies and policy rules. eve's chain in this lab used create-then-delete at the policy level; the rule-level events cover the more common "quietly edit an existing rule" variant.

**Policy and rule names by target type.** `PolicyName`/`PolicyType` come from the `PolicyEntity` target and `RuleName` from the `PolicyRule` target, found with `mv-apply` instead of a fixed index, since rule events carry both the rule and its parent policy. If the typed lookup comes back empty, `PolicyName`/`PolicyType` fall back to `OriginalTarget[0]`, the position observed in this lab.

**One row per policy event, closest prior grant only.** After the join, grants that happened after the policy event are discarded, and the latest remaining grant is kept per event. This does two things. It enforces the at-or-after direction: a policy edit made shortly before the grant can't satisfy the time math and wrongly score High. And it prevents duplicate rows when the same actor has more than one grant in the lookback.

**Timing, not the type of change, drives severity.** `IsRecentAdmin` is true when the closest prior grant is within `recentAdminWindow` (30 minutes) of the policy event. A policy change from someone who was an ordinary user an hour ago is far more suspicious than the same change from a long-standing admin, so `Severity` is `High` only in that case. `MinutesSinceAdminGrant` is real elapsed time to one decimal, not a count of minute boundaries.

False positives: a newly promoted admin doing legitimate policy work as part of onboarding a real hire (e.g. IT sets up a new joiner's day-one access policy right after their own promotion). Tighten `recentAdminWindow`, or add an allowlist of accounts expected to touch policies as part of their role.

## KQL

```kusto
// Detection: Policy Tampering Shortly After Admin Grant (Okta)
// Event types: policy.lifecycle.create/update/delete/deactivate,
//              policy.rule.create/update/delete/deactivate,
//              user.account.privilege.grant (correlation)
// MITRE:       T1556.009 - Modify Authentication Process: Conditional Access Policies
// Source:      OktaV2_CL (Okta System Log via Sentinel Okta Single Sign-On CCF connector)
// Lab:         Telemetry confirmed in Sentinel workspace law-1, Okta Integrator Free tenant
//
// TUNING NOTES:
// 1. recentAdminWindow = 30m is lab-tuned. Widen for patient attackers,
//    but that also raises the odds of flagging a freshly promoted admin's
//    normal day-one work.
// 2. tamperEvents covers all four actions for policies and rules. Narrow
//    to delete/deactivate/update only if create is too routine to alert on.
// 3. No allowlist yet. Add for production:
//    | where ActorUsername !in (expected_policy_editors)
// 4. Shares its admin-grant signal with OKTA-DET-003 - if you restrict
//    the high-risk role lists there, consider restricting recentAdmins here too.
// 5. Grants that happened after the policy event are dropped before
//    picking the closest one, so a policy edit made BEFORE the grant is not
//    "recent admin" activity and can't score High.
// 6. Only user.account.privilege.grant is correlated. An actor who became
//    admin through group.privilege.grant plus a group membership change
//    won't be flagged as a recent admin here - OKTA-DET-003 still alerts on
//    the group grant itself.
// 7. policy.rule.* events were not simulated in this lab. PolicyEntity /
//    PolicyRule are Okta's standard target types; run a test rule edit and
//    confirm PolicyName and RuleName populate as expected.
// 8. Every policy change produces a row, Medium unless IsRecentAdmin.
//    If that's too noisy as a scheduled rule, add | where IsRecentAdmin
//    before the final project to alert only on the grant-then-tamper chain.
//
let lookback = 24h;
let recentAdminWindow = 30m;
let tamperEvents = dynamic([
    "policy.lifecycle.create", "policy.lifecycle.update", "policy.lifecycle.delete", "policy.lifecycle.deactivate",
    "policy.rule.create", "policy.rule.update", "policy.rule.delete", "policy.rule.deactivate"]);
// --- Admin grants to users, for correlation ---
let recentAdmins = OktaV2_CL
| where TimeGenerated > ago(lookback)
| where EventOriginalType == "user.account.privilege.grant"
| where EventResult == "Success"
| mv-apply t = OriginalTarget on (
    summarize TypedAdmin = take_anyif(tostring(t.alternateId), tostring(t.type) == "User")
  )
| extend NewAdmin = coalesce(TypedAdmin, tostring(OriginalTarget[0].alternateId))
| project NewAdmin, GrantTime = TimeGenerated;
// --- Policy and rule events, joined against admin grants ---
OktaV2_CL
| where TimeGenerated > ago(lookback)
| where EventOriginalType in (tamperEvents)
| where EventResult == "Success"
| mv-apply t = OriginalTarget on (
    summarize
        PolicyEntry = take_anyif(t, tostring(t.type) == "PolicyEntity"),
        RuleEntry = take_anyif(t, tostring(t.type) == "PolicyRule")
  )
| extend PolicyName = coalesce(tostring(PolicyEntry.displayName), tostring(OriginalTarget[0].displayName))
| extend PolicyType = coalesce(tostring(PolicyEntry.detailEntry.policyType), tostring(OriginalTarget[0].detailEntry.policyType))
| extend RuleName = tostring(RuleEntry.displayName)
| join kind=leftouter (recentAdmins) on $left.ActorUsername == $right.NewAdmin
// Discard grants that came after this policy event, then keep the closest prior one.
| extend GrantTime = iff(GrantTime <= TimeGenerated, GrantTime, datetime(null))
| summarize GrantTime = max(GrantTime) by TimeGenerated, ActorUsername, EventOriginalType, PolicyName, PolicyType, RuleName
| extend MinutesSinceAdminGrant = round((TimeGenerated - GrantTime) / 1m, 1)
| extend IsRecentAdmin = isnotempty(GrantTime) and TimeGenerated - GrantTime <= recentAdminWindow
| extend Severity = iff(IsRecentAdmin, "High", "Medium")
| project TimeGenerated, Actor = ActorUsername, EventOriginalType, PolicyName, PolicyType, RuleName, IsRecentAdmin, MinutesSinceAdminGrant, Severity
| order by TimeGenerated asc
```
