---
title: Privileged Group Membership Addition (4728/4732/4756)
status: lab prototype
mitre:  
  - T1098.007: Account Manipulation - Additional Local or Domain Groups
source:
  - Windows 4728: A member was added to a security-enabled global group
  - Windows 4732: A member was added to a security-enabled local group
  - Windows 4756: A member was added to a security-enabled universal group
last_updated: 2026-09-27
severity: high
confidence: high
attack_simulation: atexec + Add-ADGroupMember (Domain Admins, Enterprise Admins, DnsAdmins)
notes: Fires on any addition to a watchlisted privileged group. Every alert warrants review.
---

## Summary

Detects user or machine accounts being added to privileged AD security groups.                                                                                                                                                                                         
Flags both human admin actions and SYSTEM-context additions separately so triage is easier.

## Why this matters

Getting added to Domain Admins (or equivalent) is the end goal of most AD attacks.                                                                                                                                                                                   
It converts any compromised account into full domain control: DCSync, GPO manipulation, lateral movement everywhere.

Windows logs group additions under a different event ID depending on the group's scope, so a single event ID is not enough:

| Group | Scope | Event ID |
|---|---|---|
| Domain Admins | Global | 4728 |
| Enterprise Admins, Schema Admins | Universal | 4756 |
| Administrators, Account/Server/Print/Backup Operators | Builtin domain local | 4732 |
| DnsAdmins | Domain local | 4732 |

An earlier version of this detection only watched 4728, which meant only Domain Admins was ever covered. All three event IDs also fire for any group, including ones like "Marketing-Team", so the detection filters to a privileged group watchlist.

About DnsAdmins: The DNS service on a DC runs as SYSTEM, and DnsAdmins members can load a DLL into it, making it an indirect SYSTEM escalation path.

4728 and 4756 only fire on Domain Controllers since the DC owns the group objects. 4732 also fires on member servers when their local groups change (see Signal logic).

## Signal logic

**Matching on SID, not name:** groups are identified by SID. Names can be renamed and are localized, for example "Domänen-Admins" in a German-language AD, so a name-based watchlist silently misses them. Domain Admins, Schema Admins and Enterprise Admins are matched by their well-known RIDs (-512, -518, -519). The builtin groups have fixed SIDs (S-1-5-32-544 and 548 to 551). DnsAdmins has no well-known RID and is matched by name only.

**Member servers:** a member server's local Administrators group has the same SID (S-1-5-32-544) as the domain's builtin Administrators group. Additions on member servers are kept rather than dropped, since local admin additions are also worth seeing, but they are labeled `Local (member server)` in the `Scope` column so the analyst can tell them apart from domain-wide changes.

The query then adds a suspicion flag based on who performed the add:

- **SYSTEM session (LogonId 0x3e7):** highest priority. No legitimate admin workflow adds domain group members from a SYSTEM session. Typical of C2 execution, scheduled task abuse, or tools like impacket atexec.
- **Machine account subject (ends in $), not SYSTEM:** a computer account performed the add from a normal logon session, for example a compromised machine account authenticating remotely. Computer accounts should never manage group membership. Worth investigating.
- **Human subject:** named user, could be legitimate provisioning. Check with the admin or a change ticket.

`MemberName` comes in DN format (`CN=hacker,CN=Users,DC=lab,DC=local`). The query parses out the short name for readability.

False positives: planned privileged account provisioning by IT. Do not suppress machine account or SYSTEM session events even if they look expected.

## KQL

```kusto
// Detection: Privileged Group Membership Addition
// Event IDs: 4728 (global), 4732 (domain local / builtin), 4756 (universal)
// MITRE:     T1098.007 - Additional Local or Domain Groups
// Source:    SecurityEvent (Windows Security Log, DCs and member servers)
// Lab:       Telemetry confirmed in Sentinel workspace law-1 (lab.local)
//
// TUNING NOTES:
// 1. Groups are matched by SID so renamed or localized groups are still caught.
//    DnsAdmins has no well-known RID and is matched by name.
// 2. Update known_dcs to your DC hostnames. In production use a watchlist:
//    let known_dcs = (_GetWatchlist('DomainControllers') | project Computer);
// 3. To drop member server local admin adds entirely, add:
//    | where Scope == "Domain"

let known_dcs = dynamic(["WIN-72DM6NS4BVH.lab.local"]);
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetSid endswith "-512"          // Domain Admins
    or TargetSid endswith "-518"           // Schema Admins
    or TargetSid endswith "-519"           // Enterprise Admins
    or TargetSid in ("S-1-5-32-544",       // Administrators
                     "S-1-5-32-548",       // Account Operators
                     "S-1-5-32-549",       // Server Operators
                     "S-1-5-32-550",       // Print Operators
                     "S-1-5-32-551")       // Backup Operators
    or TargetUserName =~ "DnsAdmins"       // no well-known RID
| extend Scope = iff(Computer in~ (known_dcs), "Domain", "Local (member server)")
| extend AddedMember = extract(@"CN=([^,]+)", 1, MemberName)
| extend AddedMember = iff(isempty(AddedMember), MemberSid, AddedMember)  // local adds often have no DN
| extend SuspicionFlag = case(
    SubjectLogonId == "0x3e7",          "SYSTEM session - high suspicion",
    SubjectUserName endswith "$",        "Machine account subject - review",
                                         "Human subject - verify with admin"
)
| project
    TimeGenerated,
    EventID,
    Computer,
    Scope,
    SubjectUserName,
    TargetUserName,
    TargetSid,
    AddedMember,
    MemberName,
    SubjectLogonId,
    SuspicionFlag
| sort by TimeGenerated desc
```
