---
title: OAuth Permission Grant with High-Risk Permissions - Illicit Consent Grant (Entra ID AuditLogs)
status: lab prototype
mitre:
  - T1528: Steal Application Access Token
  - T1098.003: Account Manipulation - Additional Cloud Roles
source:
  - Entra ID AuditLogs:
    - Consent to application: User or admin consent granted through a consent prompt
    - Add delegated permission grant: Delegated permissions granted, via consent or directly via Graph/PowerShell
    - Add app role assignment to service principal: Application permissions granted, via consent or directly via Graph
last_updated: 2026-09-29
severity: high
confidence: medium
attack_simulation: (1) tenant-wide admin consent for Mail.Read, offline_access and User.Read (delegated) to lab-test-app; (2) Mail.Read application permission granted to lab-test-app via Grant admin consent in the portal; (3) Mail.ReadWrite delegated grant created for lab-test-app2 via Graph PowerShell, with no consent prompt; (4) single-user consent to Microsoft Graph Command Line Tools while connecting to Graph PowerShell
notes: Severity is High when any granted scope or app role is in the high-risk list. Single-user consent by a non-admin user (the classic phishing path), grants initiated by apps, and scopes added to an existing grant via the API are in scope but were not simulated in this lab.
---

## Summary

Detects when an app is granted OAuth permissions, whether through a consent prompt or directly through Microsoft Graph, and flags grants that include high-risk scopes such as mailbox, file or directory write access. The rule reports exactly which risky scopes were granted, whether they are delegated or application permissions, and whether the grant covers one user or the entire tenant.

## Why this matters

In an illicit consent grant, the attacker registers an app in their own tenant, gives it a harmless name ("PDF Viewer", "Office Security Update") and sends a phishing link. The victim lands on the real Microsoft login page, signs in with their real password, passes real MFA, and then sees a prompt asking the app for access to their mail. One click on Accept gives the attacker tokens to read that mailbox through Microsoft Graph. With `offline_access` in the grant, the attacker also gets refresh tokens, and a password reset doesn't revoke the consent. Nothing was stolen in the classic sense, which is why it gets past controls built around credentials and MFA.

Consent-phishing detection often focuses on individual users. This rule deliberately treats tenant-wide grants as in scope too, because they are the higher-impact version: one admin click, whether the admin was tricked or compromised, grants the app the same access to every user in the tenant.

A consent prompt is also not the only way in. An attacker who already controls an admin account, or an app holding the right Graph permission, can create grants directly through the API. No prompt appears and no consent event is logged. The most dangerous version is application permissions: app-only `Mail.Read` or `full_access_as_app` lets the app read every mailbox in the tenant with no user signed in at all. In this lab, four grants cover these paths: a tenant-wide admin consent, an application permission granted in the portal, a delegated grant created through Graph PowerShell with no prompt, and a single-user consent.

## Signal logic

**Three grant paths, not one.** The rule watches `Consent to application`, `Add delegated permission grant` and `Add app role assignment to service principal`. Lab data confirmed that a delegated grant created through Graph PowerShell logs only `Add delegated permission grant`, with no consent event, so a rule watching consent alone would miss it completely.

**One alert per grant.** A portal consent logs the consent event plus the matching grant event under the same `CorrelationId`. The rule merges all rows per `CorrelationId`, so one action produces one alert, and `GrantPaths` shows which operations were involved.

**Application permissions only in the app role event.** When an application permission was granted in the portal, the accompanying consent event still logged `ConsentContext.IsAppOnly = False` and listed only the existing delegated scopes. Application permissions are therefore read from `AppRole.Value` in the app role assignment event, and `IsAppOnly` is not used.

**Tenant-wide vs single user.** `ConsentScope` comes from `ConsentContext.OnBehalfOfAll` (consent event) or `DelegatedPermissionGrant.ConsentType` (grant event), not from `IsAdminConsent`. In the lab, an admin consenting only for themselves logged `IsAdminConsent = True` with `OnBehalfOfAll = False`. `IsAdminConsent` means an admin clicked Accept, not that the grant covers everyone. Application permissions are always tenant-wide. When one action logs several events that disagree, any tenant-wide row makes the whole alert tenant-wide.

**Only newly granted scopes.** `ConsentAction.Permissions` holds the grant as `[old] => [new]`, and the right side is the full grant after the change, not only what was added. Lab data showed an unchanged scope list on both sides when an app permission was added to an app that already had delegated consent. The rule diffs old against new, so re-consenting doesn't re-alert on scopes that were already granted.

**Client app vs API target.** In the two grant events, the target service principal is the API being accessed (e.g. Microsoft Graph), not the app receiving access. The client app is read from `modifiedProperties` instead. `Add delegated permission grant` logs the client's name and AppId as empty, so a grant created purely through the API alerts without `AppName` or `AppId`. `ClientSpId` (the client service principal object ID) is always populated for pivoting.

**Exact, case-insensitive scope matching.** Scopes are split into individual values and compared against the high-risk list with `in~`. Exact matching means `Mail.Read` doesn't accidentally match `Mail.ReadBasic`. Case-insensitive matching covers scopes logged in a different casing.

**High-risk list includes permission-granting permissions.** Besides data access scopes, the list contains `AppRoleAssignment.ReadWrite.All` and `DelegatedPermissionGrant.ReadWrite.All`. An app holding either can grant itself or any other app further permissions, so they are escalation primitives in their own right.

**offline_access as an amplifier, not a trigger.** Nearly every app requests `offline_access`, so it isn't in the high-risk list on its own. It stays visible in `GrantedScopes`, since combined with mail or file access it means the access survives a password reset.

**AppId for allowlisting.** Any allowlist of approved apps should key on `AppId` (client ID), not on the service principal object ID, which is different in every tenant.

**Human and app actors.** Grants performed by a user and by an app through Graph are both handled, with `ActorType` showing which. As in ENTRA-DET-001, the same admin appeared under two different UPNs across events, so group or allowlist actors on `ActorId`. The Graph PowerShell consent also logged a Microsoft-owned `ActorIP` instead of the admin's own address, so don't treat `ActorIP` as the user's location without checking sign-in logs.

**No app allowlist yet.** Every grant fires, High with risky scopes, Medium without. Fine for a lab tenant, but production needs an allowlist of approved AppIds.

False positives: onboarding of legitimate SaaS tools that need mailbox or file access (email security, backup, CRM mail sync), users consenting to productivity apps, admins connecting with Graph PowerShell or other admin tooling (`DelegatedPermissionGrant.ReadWrite.All`). Allowlist approved AppIds, and as prevention, restrict user consent in the tenant's consent settings so only verified publishers or admin-reviewed apps can be approved.

## KQL

```kql
// Detection: OAuth Permission Grant with High-Risk Permissions (Entra ID)
// Operations:  Consent to application
//              Add delegated permission grant
//              Add app role assignment to service principal
// MITRE:       T1528 - Steal Application Access Token
//              T1098.003 - Account Manipulation: Additional Cloud Roles
// Source:      AuditLogs (Microsoft Entra ID connector, diagnostic setting)
// Lab:         Telemetry confirmed in Sentinel workspace law-1, Entra Free tenant
//
// TUNING NOTES:
// 1. Three grant paths: consent prompt (Consent to application), delegated
//    grants created directly via Graph/PowerShell (Add delegated permission
//    grant, no consent event logged), and application permissions
//    (Add app role assignment to service principal).
// 2. A portal consent logs Consent to application plus the matching grant
//    event under the same CorrelationId. Rows are merged per CorrelationId,
//    so one grant = one alert. Validated in lab.
// 3. ConsentContext.IsAppOnly stayed "False" even when an application
//    permission was granted in the portal. Application permissions are
//    only visible in the app role assignment event, so IsAppOnly is not used.
// 4. Tenant-wide vs single user comes from ConsentContext.OnBehalfOfAll /
//    DelegatedPermissionGrant.ConsentType, NOT IsAdminConsent. IsAdminConsent
//    is "True" whenever an admin consents, even just for themselves.
//    When merged rows disagree, any tenant-wide row wins.
// 5. The right side of "=>" in ConsentAction.Permissions is the FULL grant
//    after the change, not just what was added. Old and new scopes are
//    diffed so re-consenting doesn't re-alert on scopes already granted.
// 6. Add delegated permission grant has no client AppId or name (both
//    empty in lab data), only the client service principal object ID
//    (ClientSpId). API-only grants therefore alert without AppName/AppId.
// 7. Scopes added to an EXISTING delegated grant via API (PATCH) may log
//    under a different operation. Not yet checked.
// 8. DelegatedPermissionGrant.ReadWrite.All is high-risk (holder can grant
//    any delegated permission to any app). Admins using Graph PowerShell
//    will trigger it; allowlist the Graph Command Line Tools AppId
//    (14d82eec-204b-4c2f-b7e8-296a70dab67e) per admin if it gets noisy.
// 9. Allowlist approved apps on AppId (client ID), never on the service
//    principal object ID, which differs per tenant.
//
let lookback = 24h;
let highRiskScopes = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
    "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All", "Sites.ReadWrite.All",
    "Notes.Read.All", "Contacts.Read", "EWS.AccessAsUser.All", "full_access_as_user",
    "full_access_as_app",
    "Directory.ReadWrite.All", "Directory.AccessAsUser.All", "User.ReadWrite.All",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All", "RoleManagement.ReadWrite.Directory"
]);
let grants = AuditLogs
    | where TimeGenerated > ago(lookback)
    | where OperationName in ("Consent to application",
                              "Add delegated permission grant",
                              "Add app role assignment to service principal")
    | where Result == "success";
// Path 1: consent prompt (portal or phishing link). Delegated scopes only.
let consentEvents = grants
    | where OperationName == "Consent to application"
    | mv-expand Target = TargetResources
    | where tostring(Target.type) == "ServicePrincipal"
    | mv-apply mp = Target.modifiedProperties on (
        summarize
            OnBehalfOfAllRaw = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "ConsentContext.OnBehalfOfAll"),
            Permissions      = take_anyif(tostring(mp.newValue), tostring(mp.displayName) == "ConsentAction.Permissions")
      )
    | mv-apply ad = AdditionalDetails on (
        summarize AppId = take_anyif(tostring(ad.value), tostring(ad.key) == "AppId")
      )
    | extend OldScopes = split(strcat_array(coalesce(extract_all(@"Scope:\s*([^,\]]+)", tostring(split(Permissions, "=>")[0])), dynamic([])), " "), " "),
             NewScopes = split(strcat_array(coalesce(extract_all(@"Scope:\s*([^,\]]+)", tostring(split(Permissions, "=>")[1])), dynamic([])), " "), " ")
    | extend AddedScopes = set_difference(NewScopes, OldScopes, dynamic([""]))
    | extend
        ScopeText      = strcat_array(AddedScopes, " "),
        ConsentScope   = iff(OnBehalfOfAllRaw =~ "True", "Tenant-wide", "Single user"),
        PermissionType = iff(array_length(AddedScopes) > 0, "Delegated", ""),
        AppName        = tostring(Target.displayName),
        ClientSpId     = tostring(Target.id),
        ResourceName   = "";
// Path 2: delegated grant (also logged alongside portal consent; merged below)
let delegatedGrants = grants
    | where OperationName == "Add delegated permission grant"
    | mv-expand Target = TargetResources
    | where tostring(Target.type) == "ServicePrincipal"
    | mv-apply mp = Target.modifiedProperties on (
        summarize
            ScopeText   = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "DelegatedPermissionGrant.Scope"),
            ConsentType = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "DelegatedPermissionGrant.ConsentType"),
            ClientSpId  = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "ServicePrincipal.ObjectID")
      )
    | where isnotempty(ScopeText)
    | extend
        ConsentScope   = iff(ConsentType =~ "AllPrincipals", "Tenant-wide", "Single user"),
        PermissionType = "Delegated",
        AppName        = "",
        AppId          = "",
        ResourceName   = tostring(Target.displayName);
// Path 3: application permission (app role), via consent or directly via Graph
let appRoleGrants = grants
    | where OperationName == "Add app role assignment to service principal"
    | mv-expand Target = TargetResources
    | where tostring(Target.type) == "ServicePrincipal"
    | mv-apply mp = Target.modifiedProperties on (
        summarize
            ScopeText  = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "AppRole.Value"),
            AppId      = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "ServicePrincipal.AppId"),
            AppName    = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "ServicePrincipal.DisplayName"),
            ClientSpId = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "ServicePrincipal.ObjectID")
      )
    | where isnotempty(ScopeText)
    | extend
        ConsentScope   = "Tenant-wide",
        PermissionType = "Application",
        ResourceName   = tostring(Target.displayName);
union consentEvents, delegatedGrants, appRoleGrants
| extend
    ActorType = iff(isnotempty(tostring(InitiatedBy.user.id)), "User", "App"),
    ActorName = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
    ActorId   = coalesce(tostring(InitiatedBy.user.id), tostring(InitiatedBy.app.servicePrincipalId)),
    ActorIP   = tostring(InitiatedBy.user.ipAddress)
| summarize
    TimeGenerated   = min(TimeGenerated),
    GrantPaths      = make_set(OperationName),
    ActorType       = take_any(ActorType),
    ActorName       = take_any(ActorName),
    ActorId         = take_any(ActorId),
    ActorIP         = take_any(ActorIP),
    AppName         = take_anyif(AppName, isnotempty(AppName)),
    AppId           = take_anyif(AppId, isnotempty(AppId)),
    ClientSpId      = take_anyif(ClientSpId, isnotempty(ClientSpId)),
    ResourceNames   = make_set_if(ResourceName, isnotempty(ResourceName)),
    TenantWideRows  = countif(ConsentScope == "Tenant-wide"),
    PermissionTypes = make_set_if(PermissionType, isnotempty(PermissionType)),
    ScopeList       = make_list(ScopeText)
    by CorrelationId
| extend ConsentScope = iff(TenantWideRows > 0, "Tenant-wide", "Single user")
| extend GrantedScopes = set_difference(split(strcat_array(ScopeList, " "), " "), dynamic([""]))
| where array_length(GrantedScopes) > 0
| mv-apply s = GrantedScopes on (
    where tostring(s) in~ (highRiskScopes)
    | summarize RiskyScopes = make_set(tostring(s))
  )
| extend Severity = iff(array_length(RiskyScopes) > 0, "High", "Medium")
| project TimeGenerated, GrantPaths, ActorType, ActorName, ActorId, ActorIP,
          AppName, AppId, ClientSpId, ResourceNames, ConsentScope, PermissionTypes,
          GrantedScopes, RiskyScopes, Severity, CorrelationId
```
