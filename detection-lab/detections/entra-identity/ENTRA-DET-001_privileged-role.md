---
title: New Privileged Role Assignment - Privilege Escalation via Entra ID Directory Role (Entra ID AuditLogs)
status: lab prototype
mitre:
  - T1098.003: Account Manipulation - Additional Cloud Roles
source:
  - Entra ID AuditLogs:
    - Add member to role: Directory role assigned to a user, service principal or group
    - Add eligible member to role: PIM eligible assignment (not simulated)
last_updated: 2026-09-29
severity: high
confidence: medium
attack_simulation: audit-test (no roles initially) granted Global Administrator by the tenant's existing Global Administrator account
notes: Severity is High only when the role's TemplateId is in the high-risk list; other role grants stay Medium. PIM eligible assignments and role grants to groups or service principals are in scope but were not simulated in this lab. Adding a member to a role-assignable group that already holds a role is out of scope.
---

## Summary

Detects when a user, service principal or group is assigned an Entra ID directory role, flagging high-risk roles (Global Administrator, Privileged Role Administrator, Application Administrator and others) as High severity. Roles are identified by their fixed TemplateId rather than display name, and the rule works for both human and app-initiated grants.

## Why this matters

A Global Administrator can do anything in the tenant: create backdoor accounts, disable MFA and Conditional Access, read every mailbox through app permissions, and cut the SIEM off by removing the diagnostic setting that streams these logs. That makes a second admin account one of the first things an attacker sets up after compromising the first one. If the SOC later finds and resets the original account, the backdoor keeps full control.

Attackers also avoid the obvious version. Instead of a new user, they give the role to a guest account, to a service principal they hold a secret for, or to a role-assignable group they can add themselves to. Some high-impact roles don't even have "Admin" in their name. Partner Tier2 Support could reset Global Administrator passwords and is hidden from the portal's role list. Microsoft blocked new assignments to it in August 2026, but existing assignments still work, so it stays in the high-risk list and is worth auditing separately. In this lab, the grant simulates an attacker who already controls an admin account promoting a second account, audit-test, to Global Administrator.

## Signal logic

**Role match by TemplateId.** The role is read from `Role.TemplateId` inside `TargetResources.modifiedProperties`. TemplateIds are identical for built-in roles in every tenant, so the match doesn't depend on display names or on name patterns like "contains Admin". `Role.DisplayName` is still extracted for readability.

**Target extraction by type, not position.** `TargetResources` holds both the principal receiving the role and the role object itself. `mv-expand` splits them, and only targets of type `User`, `ServicePrincipal` or `Group` are kept, so grants to apps and role-assignable groups are covered, not just users.

**Human and app actors.** `InitiatedBy` has two shapes: `.user` for portal and user actions, `.app` when a service principal assigns the role through Microsoft Graph. `coalesce` pulls actor name and ID from whichever exists, and `ActorType` shows which one it was.

**Actor ID over UPN.** In this lab, the same admin was logged as both `name@pm.me` and `name_pm.me#EXT#@tenant` across different events. Any allowlist or grouping on the actor should use `ActorId`.

**PIM handling.** Eligible assignments (`Add eligible member to role`) are matched with `has_any`, since an eligible Global Administrator assignment is a quieter form of the same persistence. PIM activations, initiated by the `MS-PIM` service, are excluded because they represent someone using a role they already had, not a new grant. Neither path was validated here, since PIM requires Entra ID P2.

**High-risk role list, not a flat severity.** Only TemplateIds in the high-risk list escalate to `High`. Other role grants stay `Medium`, so routine lower-privilege assignments don't flood the queue but still produce a record. `IsGuestTarget` flags grants to external accounts (`#EXT#` in the UPN) for faster triage.

**Out of scope: joining an already-privileged group.** The rule fires when a role is assigned to a group, not when someone is later added to a group that already holds one. That change logs as `Add member to group` and gives the new member the role just the same. Covering it needs a separate rule that knows which groups currently hold high-risk roles.

**No granter allowlist yet.** The rule fires on every matching grant regardless of who performed it. Fine for a single-admin lab tenant, but a production tenant should allowlist expected admin-granting accounts by `ActorId`.

False positives: legitimate onboarding of a new admin, planned role changes during a reorg, helpdesk assigning lower-tier roles (these land as Medium). Add an allowlist of expected granter IDs, or correlate against a change-ticket system in a more mature environment.

## KQL

```kql
// Detection: New Privileged Role Assignment (Entra ID)
// Operations:  Add member to role, Add eligible member to role (PIM)
// MITRE:       T1098.003 - Account Manipulation: Additional Cloud Roles
// Source:      AuditLogs (Microsoft Entra ID connector, diagnostic setting)
// Lab:         Telemetry confirmed in Sentinel workspace law-1, Entra Free tenant
//
// TUNING NOTES:
// 1. Roles are matched by TemplateId, not display name. TemplateIds are
//    fixed for built-in roles across every tenant. Only Global Administrator
//    (62e90394...) was observed in this lab; the rest of the list is
//    Microsoft's documented built-in IDs.
// 2. PIM variants (eligible assignments) are matched via has_any, and PIM
//    activations (initiated by MS-PIM) are excluded. Both approaches adopted
//    from Microsoft's built-in templates; not validated here (PIM needs P2).
// 3. InitiatedBy has two shapes: .user for portal/user actions, .app when a
//    service principal grants the role via Graph. Both are handled.
// 4. Actor UPN is not stable (the same admin logged as both
//    name@pm.me and name_pm.me#EXT#@tenant). Allowlist on ActorId, not UPN.
// 5. No granter allowlist yet. Add for production:
//    | where ActorId !in (expected_admin_granter_ids)
//
let lookback = 24h;
let highRiskRoleTemplateIds = dynamic([
    "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", // Privileged Authentication Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7", // Cloud Application Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", // Conditional Access Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", // Hybrid Identity Administrator
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"  // Partner Tier2 Support (retired; new assignments blocked since Aug 2026)
]);
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| where Result == "success"
| mv-expand Target = TargetResources
| where tostring(Target.type) in ("User", "ServicePrincipal", "Group")
| mv-apply mp = Target.modifiedProperties on (
    summarize
        RoleTemplateId = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "Role.TemplateId"),
        RoleName       = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "Role.DisplayName")
  )
| extend
    ActorType = iff(isnotempty(tostring(InitiatedBy.user.id)), "User", "App"),
    ActorName = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
    ActorId   = coalesce(tostring(InitiatedBy.user.id), tostring(InitiatedBy.app.servicePrincipalId)),
    ActorIP   = tostring(InitiatedBy.user.ipAddress),
    TargetType = tostring(Target.type),
    TargetName = coalesce(tostring(Target.userPrincipalName), tostring(Target.displayName)),
    TargetId   = tostring(Target.id)
| where ActorName !in ("MS-PIM", "MS-PIM-Fairfax")
| extend IsGuestTarget = TargetName has "#EXT#"
| extend Severity = iff(RoleTemplateId in (highRiskRoleTemplateIds), "High", "Medium")
| project TimeGenerated, OperationName, ActorType, ActorName, ActorId, ActorIP,
          TargetType, TargetName, TargetId, IsGuestTarget, RoleName, RoleTemplateId,
          Severity, CorrelationId
```
