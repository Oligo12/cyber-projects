---
title: Credential Dumping - DCSync (4662)
status: lab prototype
mitre:
  - T1003.006: OS Credential Dumping - DCSync
source:
  - Windows 4662: An operation was performed on an object
last_updated: 2026-09-27
severity: high
confidence: high
attack_simulation: impacket-secretsdump
notes: Explicit DC allowlist required - blanket exclusion of $ accounts introduces a blind spot for compromised workstation machine accounts.
---

## Summary

Detects suspicious use of AD replication rights by non-DC accounts, indicating a likely DCSync attack. Filters 4662 events for specific DS-Replication GUIDs that are only legitimately used by Domain Controllers and directory sync accounts.

## Prerequisites

4662 for replication rights is only logged if both of these are in place:

- Advanced Audit Policy: DS Access > Audit Directory Service Access (Success) on Domain Controllers.
- A SACL on the domain root object (`DC=lab,DC=local`) auditing Everyone for the three replication extended rights.

Without the SACL, the attack still works but produces no 4662 events, and the query returns nothing.

## Why this matters

DCSync abuses legitimate AD replication protocols to pull password hashes directly from a DC without touching LSASS. Any account with `DS-Replication-Get-Changes-All` rights can dump credentials for every account in the domain, including the krbtgt hash which enables Golden Ticket attacks.

4662 fires on any AD object operation and is extremely noisy unfiltered. Three specific GUIDs in the Properties field identify replication access:

- `{1131f6aa}` - `DS-Replication-Get-Changes`: replicates non-secret attributes (user metadata, group memberships, GPO data). Alone, no credential access.
- `{1131f6ad}` - `DS-Replication-Get-Changes-All`: unlocks secret attributes including NTLM hashes and Kerberos keys. This is the critical right.
- `{89e95b76}` - `DS-Replication-Get-Changes-In-Filtered-Set`: used in some filtered replication scenarios, less common.

Impacket-secretsdump requests both `1131f6aa` and `1131f6ad` simultaneously, mirroring how a real DC initiates replication. This generates a burst of 4662 events, one per user object, all within milliseconds. In this lab: 24 events in 56ms across ~8 user objects.

## Signal logic

**GUID filter:** filters Properties field for any of the three replication GUIDs using `has_any`. Cheap full-text index lookup runs before any extract or summarize.

**AccessMask `0x100`:** Control Access, the access type used when an extended right (such as the replication rights) is exercised. Filters out reads and writes, cutting noise from other 4662 operations on AD objects.
 
**DC allowlist over blanket $ exclusion:** a blanket `!endswith "$"` filter has a real blind spot.                                                                                                                                                                         
A compromised workstation (`DESKTOP-123$`) running DCSync would be silently excluded. The correct approach is an explicit allowlist of known DC machine accounts. Anything not on the list triggers the alert, including unknown machine accounts.

Azure AD Connect / MSOL accounts are excluded separately since they legitimately hold replication rights for Entra hybrid sync. In environments without hybrid sync, remove that exclusion entirely.

**Summarize:**                                                                                                                                                                                                                                                               
collapses the burst of per-object events into a single alert row with EventCount and FirstSeen/LastSeen to show the dump duration.                                                                                                                        
`make_set` on ReplicationRight shows which rights were exercised, helping the analyst assess impact immediately: seeing `DS-Replication-Get-Changes-All` confirms credential access and not just reconnaissance.

**Source IP enrichment:** 4662 records who performed the replication but not from where. The query joins back to the 4624 logon event on the same DC using the logon ID (`SubjectLogonId` in 4662 equals `TargetLogonId` in 4624), which recovers the source IP of the session. In this lab that resolves svc-sql's replication session to Kali at 10.10.10.50.

False positives: legitimate service accounts with replication rights are themselves a misconfiguration and worth investigating. The only expected traffic from the replication GUIDs is DC machine accounts and known sync accounts, both explicitly allowlisted.

## KQL

```kusto
// Detection: DCSync - Suspicious AD Replication Rights Usage
// Event ID:  4662 - operation performed on an AD object
//            4624 - logon (source IP enrichment)
// MITRE:     T1003.006 - OS Credential Dumping: DCSync
// Source:    SecurityEvent (Windows Security Log, DC only)
// Lab:       Telemetry confirmed in Sentinel workspace law-1 (lab.local)
//
// TUNING NOTES:
// 1. Update known_dcs to match your actual DC machine account names.
//    In production, replace with a Sentinel watchlist:
//    let known_dcs = (_GetWatchlist('DomainControllers') | project dcAccount);
// 2. Remove known_sync_accounts exclusion if no hybrid Entra sync is in use.
// 3. Do NOT replace the DC allowlist with a blanket !endswith "$" filter -
//    that silently misses DCSync from compromised workstation machine accounts.
// 4. Allowlist comparison is case-insensitive (!in~).

let known_dcs = dynamic(["WIN-72DM6NS4BVH$"]);
let known_sync_accounts = dynamic(["MSOL_", "ADConnect"]);
SecurityEvent
| where EventID == 4662
| where AccessMask == "0x100"
| where Properties has_any ("1131f6ad", "1131f6aa", "89e95b76")
| where SubjectUserName !in~ (known_dcs)
| where not(SubjectUserName has_any (known_sync_accounts))
| extend ReplicationRight = case(
    Properties has "1131f6ad", "DS-Replication-Get-Changes-All (credential access)",
    Properties has "89e95b76", "DS-Replication-Get-Changes-In-Filtered-Set",
    Properties has "1131f6aa", "DS-Replication-Get-Changes",
    "Unknown"
)
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    RightsObserved = make_set(ReplicationRight)
    by SubjectUserName, SubjectDomainName, SubjectLogonId, Computer, bin(TimeGenerated, 1m)
| join kind=leftouter (
    SecurityEvent
    | where EventID == 4624
    | project TargetLogonId, Computer, SourceIp = IpAddress, SourceLogonType = LogonType
) on $left.SubjectLogonId == $right.TargetLogonId, $left.Computer == $right.Computer
| project-away TargetLogonId, Computer1
| order by FirstSeen desc
```
