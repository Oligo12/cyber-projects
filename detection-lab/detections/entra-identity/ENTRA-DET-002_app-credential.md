---
title: Credential Added to Application or Service Principal - Persistence via App Credentials (Entra ID AuditLogs)
status: lab prototype
mitre:
  - T1098.001: Account Manipulation - Additional Cloud Credentials
source:
  - Entra ID AuditLogs:
    - Update application – Certificates and secrets management: Secret or certificate added to an app registration
    - Add service principal credentials: Secret or certificate added to a service principal (not simulated)
    - Add application: App creation, used only for severity context
last_updated: 2026-09-29
severity: high
confidence: medium
attack_simulation: lab-test-app registered by the tenant's Global Administrator, then a client secret (lab-secret) added to it one minute later
notes: Severity drops to Medium when the same actor created the app within the last 7 days, so the lab simulation fires Medium by design. Credentials added to service principals and credentials added by apps (instead of users) are in scope but were not simulated in this lab.
---

## Summary

Detects when a new secret or certificate is added to an Entra ID app registration or service principal. The rule compares the key list before and after each change, so it only fires when a credential actually appears, and it rates a new credential on an established app higher than one added during initial app setup.

## Why this matters

An app with a credential can log in as itself. No user password, no MFA prompt, and resetting user passwords doesn't touch it. That makes adding a credential to an existing app one of the most reliable cloud persistence techniques: the attacker picks an app that already holds strong permissions (read all mail, write to the directory), adds their own secret, and keeps access long after the compromised admin account is cleaned up. This was a core technique in the SolarWinds intrusion.

The quieter variant targets the service principal instead of the app registration. A credential on the service principal works the same way but doesn't show up in the App registrations view, where admins usually look. A compromised app that holds `Application.ReadWrite.All` can also add secrets to other apps through Microsoft Graph, with no human account involved at all. In this lab, the secret simulates the attacker's own credential being planted on an app.

## Signal logic

**Operation match with `has`, not `==`.** The update operation's name contains an en dash and a trailing space (`"Update application – Certificates and secrets management "`). An exact match with a normal hyphen silently returns nothing.

**Old vs new key comparison.** Creating an app also logs a "Certificates and secrets management" event, but with no key added (`KeyDescription` goes from `[]` to `[]`). The rule extracts every `KeyIdentifier` from the old and new values and only keeps keys that weren't there before. Validation against lab data caught a null-handling bug here: when the new value is empty, `extract_all` returns null, which `mv-apply` treated as one empty key, so app creation still fired. Fixed by discarding empty key IDs before the comparison.

**Login credentials only.** Only keys with `KeyUsage=Verify` count: secrets and certificates used to authenticate as the app. `KeyUsage=Sign` (SAML token-signing certificates) is excluded, since those rotate routinely for SSO apps.

**App registrations and service principals.** Both target types are in scope, so the service principal variant isn't filtered out. The service principal path assumes the same `KeyDescription` property and hasn't been validated yet.

**Human and app actors.** `InitiatedBy.user` and `InitiatedBy.app` are both handled, so a credential added by an app through Graph fires the same way as one added in the portal.

**Severity by app age.** The rule looks back 7 days for the app's `Add application` event. If the same actor created the app and then added a credential, that's the normal developer workflow and lands as `Medium`. A credential appearing on an app that's older than that, or was created by someone else, stays `High`. That's why the lab simulation, where the app was created one minute before the secret, fires Medium.

**AppId for pivoting.** The app's client ID is pulled from `AdditionalDetails`, since that's the ID that shows up when the app later signs in (e.g. in service principal sign-in logs).

False positives: planned secret rotation before expiry on existing apps (this lands as High and is the main source of noise), CI/CD pipelines or automation that rotate credentials, certificate renewals. Allowlist the automation's `ActorId` and expected app owners, or correlate against a change-ticket system in a more mature environment.

## KQL

```kql
// Detection: Credential Added to Application or Service Principal (Entra ID)
// Operations:  Update application – Certificates and secrets management
//              Add service principal credentials
// MITRE:       T1098.001 - Account Manipulation: Additional Cloud Credentials
// Source:      AuditLogs (Microsoft Entra ID connector, diagnostic setting)
// Lab:         Telemetry confirmed in Sentinel workspace law-1, Entra Free tenant
//
// TUNING NOTES:
// 1. OperationName contains an en dash and a trailing space, so it is
//    matched with has, never ==.
// 2. App creation also logs a "Certificates and secrets management" event
//    with no key added (KeyDescription [] => []). The rule compares old vs
//    new KeyIdentifiers and only fires when a new key actually appears.
// 3. "Add service principal credentials" (credential on the SP, not the
//    app registration) was not simulated. Assumed to carry the same
//    KeyDescription property; confirm before relying on it.
// 4. Severity drops to Medium when the same actor created the app within
//    newAppWindow (normal dev workflow: register app, add secret). A new
//    secret on an existing app is the real attacker pattern and stays High.
// 5. No actor allowlist yet. Add for production (key on ActorId, not UPN).
// 6. KeyUsage=Sign (SAML token-signing certificates, routine SSO rollover)
//    is excluded, following Microsoft's built-in templates.
//
let lookback = 24h;
let newAppWindow = 7d;
let recentlyCreatedApps = AuditLogs
    | where TimeGenerated > ago(newAppWindow)
    | where OperationName == "Add application"
    | where Result == "success"
    | extend AppObjectId = tostring(TargetResources[0].id),
             CreatorId   = coalesce(tostring(InitiatedBy.user.id), tostring(InitiatedBy.app.servicePrincipalId))
    | summarize AppCreated = min(TimeGenerated) by AppObjectId, CreatorId;
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has "Certificates and secrets management"
     or OperationName == "Add service principal credentials"
| where Result == "success"
| mv-expand Target = TargetResources
| where tostring(Target.type) in ("Application", "ServicePrincipal")
| mv-apply mp = Target.modifiedProperties on (
    where tostring(mp.displayName) == "KeyDescription"
    | project OldKeys = tostring(mp.oldValue), NewKeys = tostring(mp.newValue)
  )
| extend OldKeyIds = coalesce(extract_all(@"KeyIdentifier=([0-9a-fA-F-]{36})", OldKeys), dynamic([]))
| extend NewKeyEntries = extract_all(@"KeyIdentifier=([0-9a-fA-F-]{36}),KeyType=([^,]+),KeyUsage=([^,]+),DisplayName=([^\]]*)\]", NewKeys)
| mv-apply k = NewKeyEntries on (
    where isnotempty(tostring(k[0])) and not(set_has_element(OldKeyIds, tostring(k[0])))
          and tostring(k[2]) =~ "Verify"
    | summarize AddedKeyIds   = make_list(tostring(k[0])),
                AddedKeyTypes = make_set(tostring(k[1])),
                AddedKeyNames = make_list(tostring(k[3]))
  )
| where array_length(AddedKeyIds) > 0
| mv-apply ad = AdditionalDetails on (
    summarize AppId = take_anyif(tostring(ad.value), tostring(ad.key) == "AppId")
  )
| extend
    ActorType  = iff(isnotempty(tostring(InitiatedBy.user.id)), "User", "App"),
    ActorName  = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
    ActorId    = coalesce(tostring(InitiatedBy.user.id), tostring(InitiatedBy.app.servicePrincipalId)),
    ActorIP    = tostring(InitiatedBy.user.ipAddress),
    TargetType = tostring(Target.type),
    TargetName = tostring(Target.displayName),
    TargetId   = tostring(Target.id)
| join kind=leftouter recentlyCreatedApps on $left.TargetId == $right.AppObjectId
| extend CreatedBySameActorRecently = isnotnull(AppCreated) and CreatorId == ActorId
| extend Severity = iff(CreatedBySameActorRecently, "Medium", "High")
| project TimeGenerated, OperationName, ActorType, ActorName, ActorId, ActorIP,
          TargetType, TargetName, TargetId, AppId, AddedKeyTypes, AddedKeyNames,
          AppCreated, CreatedBySameActorRecently, Severity, CorrelationId
```
