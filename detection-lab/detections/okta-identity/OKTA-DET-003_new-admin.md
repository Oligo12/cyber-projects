---
title: New Admin Role Grant - Privilege Escalation via Super Organization Administrator (Okta System Log)
status: lab prototype
mitre:
  - T1098.003: Account Manipulation - Additional Cloud Roles
source:
  - Okta System Log:
    - user.account.privilege.grant: Admin role granted to a user account
    - group.privilege.grant: Admin role granted to a group
last_updated: 2026-09-28
severity: medium
confidence: medium
attack_simulation: eve (no admin rights initially) granted Super Organization Administrator by the tenant's existing Super Admin account
notes: Severity elevates to High only when the granted role matches the high-risk role lists (Super Admin, Org Admin); lower-tier role grants stay Medium. Group grants are in scope but were not simulated in this lab.
---

## Summary

Detects when a user account or a group is granted an Okta admin role, flagging high-risk roles (Super Administrator, Organization Administrator) as High severity. Fires directly off the privilege-grant event itself rather than depending on any prior risk scoring.

## Why this matters

An admin role grant is one of the most direct paths to full tenant compromise. Once an attacker holds one, they can create backdoor accounts, weaken or disable MFA policies, and cut off the SIEM's view of the tenant by revoking the API token the connector uses to pull the logs. The Okta System Log itself can't be edited by an admin, but Sentinel only sees what the connector keeps pulling.

Microsoft's built-in "High-Risk Admin Activity" analytic rule only fires when the admin operation correlates with a login Okta's risk engine already flagged as high risk. A grant performed from a clean-reputation IP, or by an account that was compromised earlier without tripping the risk engine, doesn't trigger it. The Okta solution does ship an "Admin privilege granted (Okta)" query that looks at the grant event directly, but it's a hunting query, not a scheduled rule - someone has to run it. This detection turns that signal into a scheduled alert, so privilege escalation that started quietly still produces an incident. In this lab, the grant simulates an attacker who already controls an admin account (or a malicious insider) promoting a second account, eve, who then uses her new rights for policy tampering ([`OKTA-DET-004`](OKTA-DET-004_policy-tampering.md)).

## Signal logic

**User and group grants.** Both `user.account.privilege.grant` and `group.privilege.grant` are in scope. Without the group event, an attacker could assign an admin role to a group and then add themselves to it, and the rule would never fire.

**Target extraction by type, not position.** `OriginalTarget` is a dynamic array, and Okta doesn't guarantee its order. `mv-apply` walks the array and pulls the principal out by its `type`: `User` into `TargetUser`, `UserGroup` into `TargetGroup`. Unlike the role fields, `TargetUser` has no positional fallback: a group grant has no `User` target, so an empty `TargetUser` there is correct, not a failed lookup.

**High-risk role match by value.** The role is found by searching the whole target array for an entry whose `id` is in `highRiskRoleIds` or whose `displayName` is in `highRiskRoleNames`, so the match doesn't depend on where the role sits in the array. Both lists hold multiple spellings because Okta's System Log role ids (e.g. `SuperOrgAdmin`, the value observed in this lab) don't use the same format as the API role types (`SUPER_ADMIN`, `ORG_ADMIN`). For grants that don't match, `RoleId`/`RoleName` fall back to `OriginalTarget[2]`, the position observed in this lab.

**High-risk role list, not a flat severity.** Only grants of roles in those lists escalate to `High`; other granted roles (e.g. a scoped app admin) stay `Medium`, so the rule doesn't flood an analyst with alerts for routine, lower-privilege role assignments.

**No granter allowlist yet.** The rule fires on every matching grant regardless of who performed it. Fine for a 5-user lab where every admin grant is worth a look, but a production tenant should add an allowlist of expected admin-granting accounts (e.g. the IT team's admin accounts) to cut noise from routine onboarding.

False positives: legitimate onboarding of a new admin during a hire or role change, planned privilege changes during a reorg. Add an allowlist of expected granter accounts, or correlate against a change-ticket system in a more mature environment.

## KQL

```kusto
// Detection: New Admin Role Grant - Privilege Escalation (Okta)
// Event types: user.account.privilege.grant, group.privilege.grant
// MITRE:       T1098.003 - Account Manipulation: Additional Cloud Roles
// Source:      OktaV2_CL (Okta System Log via Sentinel Okta Single Sign-On CCF connector)
// Lab:         Telemetry confirmed in Sentinel workspace law-1, Okta Integrator Free tenant
//
// TUNING NOTES:
// 1. highRiskRoleIds / highRiskRoleNames cover Super Admin and Org Admin.
//    Only SuperOrgAdmin / "Super Organization Administrator" has been
//    observed in this lab. Grant Org Admin to a test user and confirm the
//    exact id and displayName it logs, then trim the lists to the values
//    your tenant actually produces. Extend them to match whatever else
//    your tenant treats as high-privilege.
// 2. lookback = 24h - widen if you expect slow, spaced-out escalation.
// 3. No granter allowlist yet. Add for production:
//    | where ActorUsername !in (expected_admin_granters)
// 4. Doesn't depend on Okta's own risk-flagged-login signal, unlike
//    Microsoft's High-Risk Admin Activity rule.
// 5. group.privilege.grant was not simulated in this lab. TargetGroup
//    extraction assumes Okta's standard "UserGroup" target type, and the
//    RoleId/RoleName fallback position (OriginalTarget[2]) is only
//    confirmed for user grants. Run a test group grant and check both.
// 6. A group grant elevates every current and future member of that group.
//    Follow up with group.user_membership.add events on TargetGroup.
//
let lookback = 24h;
let highRiskRoleIds = dynamic(["SuperOrgAdmin", "OrgAdmin", "SUPER_ADMIN", "ORG_ADMIN"]);
let highRiskRoleNames = dynamic(["Super Organization Administrator", "Super Administrator", "Organization Administrator"]);
OktaV2_CL
| where TimeGenerated > ago(lookback)
| where EventOriginalType in ("user.account.privilege.grant", "group.privilege.grant")
| where EventResult == "Success"
| mv-apply t = OriginalTarget on (
    summarize
        TargetUser = take_anyif(tostring(t.alternateId), tostring(t.type) == "User"),
        TargetGroup = take_anyif(tostring(t.displayName), tostring(t.type) == "UserGroup"),
        HighRiskRoleId = take_anyif(tostring(t.id), tostring(t.id) in (highRiskRoleIds) or tostring(t.displayName) in (highRiskRoleNames)),
        HighRiskRoleName = take_anyif(tostring(t.displayName), tostring(t.id) in (highRiskRoleIds) or tostring(t.displayName) in (highRiskRoleNames))
  )
| extend RoleId = coalesce(HighRiskRoleId, tostring(OriginalTarget[2].id))
| extend RoleName = coalesce(HighRiskRoleName, tostring(OriginalTarget[2].displayName))
| extend Severity = iff(isnotempty(HighRiskRoleId), "High", "Medium")
| project TimeGenerated, EventOriginalType, GrantedBy = ActorUsername, TargetUser, TargetGroup, RoleId, RoleName, Severity
```
