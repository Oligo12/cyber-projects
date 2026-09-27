---
title: GPO Linking or Modification (5136)
status: lab prototype
mitre:
  - T1484.001: Domain or Tenant Policy Modification - Group Policy Modification
source:
  - Windows 5136: A directory service object was modified
last_updated: 2026-09-27
severity: high
confidence: medium
attack_simulation: New-GPO + New-GPLink (local DC01 PowerShell session)
notes: groupPolicyContainer events benefit from an environment-specific GPO watchlist to reduce noise from routine admin activity.
---

## Summary

Detects GPO linking to a domain object or OU via `gPLink` attribute writes, and modifications to `groupPolicyContainer` objects which indicate changes to GPO settings or metadata. The latter can be noisy without an environment-specific watchlist.

## Why this matters

GPOs apply to every machine and user in their scope. 
An attacker with Domain Admin access can abuse this to push changes across the entire domain in one move: disable Defender on all endpoints, add a malicious startup script, or modify audit policy to blind the SIEM.                                                    
It's one of the highest-leverage actions available after domain compromise.

5136 is a directory service change event that fires on AD object attribute writes.                                                                                                                                                                                           
Two scenarios are relevant here:

- `gPLink` modified on a `domainDNS` or `organizationalUnit` object: a GPO was linked or unlinked. Relatively rare in normal operations, low FP rate.
- `groupPolicyContainer` object modified: GPO metadata updated, which happens every time any setting inside the GPO changes. Can be noisy in environments with active GPO management.

5136 only fires on Domain Controllers since the DC owns these objects.

## Signal logic

Every GPO attribute change generates two 5136s in sequence: a deletion of the old value (`%%14675`) followed by an addition of the new value (`%%14674`). The query alerts on the addition only, since that is the resulting state, and uses the deletion only as `PreviousValue` context.

Early `has` filters on `gPLink` and `groupPolicyContainer` run before the `extract()` calls because KQL's `has` operator is cheap at scale. The regex extracts are expensive and should only run on the small subset of rows that pass the pre-filter.

Fields in 5136 are not parsed into named Sentinel columns like most Security events. Everything useful (`ObjectClass`, `AttributeLDAPDisplayName`, `AttributeValue`, `ObjectDN`) is found in the raw XML blob and requires `extract()`.

**Reading a gPLink change:** the new `AttributeValue` contains the entire gPLink after the change, which lists every GPO linked to that object, not only the new one. To show what changed, the query joins the matching deletion event (`%%14675`, same `OpCorrelationID` and attribute) and puts the old value next to the new one in `PreviousValue`. The GPO present in `AttributeValue` but missing from `PreviousValue` is the newly linked one. The same comparison shows unlinking: in this lab, Remove-GPLink produced a row where the Test-Link GUID is present in `PreviousValue` and missing from `AttributeValue`.

**Client-side extension changes:** writes to `gPCMachineExtensionNames` or `gPCUserExtensionNames` on a `groupPolicyContainer` mean a new type of setting was added to the GPO, for example a scheduled task or startup script. This is how GPO abuse tools such as SharpGPOAbuse show up in AD, so these writes are flagged separately in `ChangeType` from routine `versionNumber` increments.

**No-op rewrites and GPO creation:** in this lab, a single New-GPLink produced three gPLink writes, but only one actually changed the value. The other two rewrote the same list. Rows where `PreviousValue` equals `AttributeValue` are dropped. Creating a GPO (New-GPO) writes every initial attribute of the new object; purely structural ones (`cn`, `gPCFunctionalityVersion`) are dropped. The rest keep their normal labels, so a new GPO appears as a cluster of rows with the same timestamp and an empty `PreviousValue`, anchored by the "New GPO created" row. For example, the initial `versionNumber` of 0 shows up as "GPO settings edited". Two attributes are flagged because they matter on existing GPOs: `gPCFileSysPath` changing on an existing GPO means it now points somewhere else for its policy files, a known abuse path; and `flags` controls whether the user or computer half of a GPO is disabled (0 = all enabled, 1 = user settings disabled, 2 = computer settings disabled, 3 = all disabled).

False positives:
- `gPLink` events: low. GPO linking is infrequent in normal operations.
- `groupPolicyContainer` events: medium to high. Every GPO edit increments  `versionNumber` and fires 5136. Add an environment-specific watchlist of sensitive GPO GUIDs to the `where groupPolicyContainer` branch to reduce this to near zero.

## Limitations

5136 only sees the Active Directory side of a GPO. The actual policy content (scripts, scheduled task XML, registry.pol) lives in SYSVOL on the DC's file system. An attacker who edits files in SYSVOL directly changes what the GPO does, and the only AD-side trace is a `versionNumber` increment. Seeing the content change requires file share auditing on SYSVOL (5145) or file integrity monitoring.                                                                                                                                                                                                               
Deleting a GPO removes the groupPolicyContainer object, which logs 5141 (directory service object deleted), not 5136. GPO deletion is therefore not covered by this detection.

## KQL

```kusto
// Detection: GPO Linking or Modification
// Event ID:  5136 - directory service object modified
// MITRE:     T1484.001 - Group Policy Modification
// Source:    SecurityEvent (Windows Security Log, DC only)
// Lab:       Telemetry confirmed in Sentinel workspace law-1 (lab.local)
//
// TUNING NOTES:
// 1. groupPolicyContainer events fire on any GPO edit (versionNumber increments).
//    In production, extend the groupPolicyContainer branch with a watchlist:
//      or (ObjectClass == "groupPolicyContainer" and ObjectDN has_any (sensitive_gpo_guids))
//    where sensitive_gpo_guids is a dynamic list of GUIDs for your high-value GPOs
//    (default domain policy, security baselines, etc.)
// 2. ChangeType "New client-side extension" is the highest-value row type.
//    Consider a separate high-severity rule for it alone.

let gpo_changes = SecurityEvent
| where EventID == 5136
| where EventData has "gPLink" or EventData has "groupPolicyContainer"
| extend OperationType = extract(@'OperationType">([^<]+)', 1, EventData)
| extend ObjectClass = extract(@'ObjectClass">([^<]+)', 1, EventData)
| extend AttributeName = extract(@'AttributeLDAPDisplayName">([^<]+)', 1, EventData)
| extend AttributeValue = extract(@'AttributeValue">([^<]+)', 1, EventData)
| extend ObjectDN = extract(@'ObjectDN">([^<]+)', 1, EventData)
| extend OpCorrelationID = extract(@'OpCorrelationID">([^<]+)', 1, EventData)
| where (AttributeName == "gPLink" and ObjectClass in ("domainDNS", "organizationalUnit"))
    or ObjectClass == "groupPolicyContainer"; // add environment-specific GPO watchlist here to reduce FP
gpo_changes
| where OperationType == "%%14674"   // value added (the new state)
| join kind=leftouter (
    gpo_changes
    | where OperationType == "%%14675"   // value deleted (the previous state)
    | project OpCorrelationID, AttributeName, PreviousValue = AttributeValue
) on OpCorrelationID, AttributeName
| where AttributeName !in ("cn", "gPCFunctionalityVersion")   // creation metadata, no signal
| where PreviousValue != AttributeValue                        // drop no-op rewrites
| extend ChangeType = case(
    AttributeName == "gPLink", "GPO link changed",
    AttributeName in ("gPCMachineExtensionNames", "gPCUserExtensionNames"), "New client-side extension - high interest",
    AttributeName == "gPCFileSysPath" and isnotempty(PreviousValue), "SYSVOL path changed - high interest",
    AttributeName == "gPCFileSysPath", "SYSVOL path set (new GPO)",
    AttributeName == "objectClass", "New GPO created",
    AttributeName == "flags", "GPO enabled/disabled state changed",
    AttributeName == "displayName", "GPO display name changed",
    AttributeName == "versionNumber", "GPO settings edited",
    strcat("Other: ", AttributeName)
)
| project TimeGenerated, SubjectUserName, SubjectLogonId, ChangeType, ObjectClass,
          AttributeName, PreviousValue, AttributeValue, ObjectDN, OpCorrelationID
| sort by TimeGenerated desc
```
