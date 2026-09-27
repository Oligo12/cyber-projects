---
title: Kerberoasting - Suspicious TGS Requests (4769)
status: lab prototype
mitre:
  - T1558.003: Steal or Forge Kerberos Tickets - Kerberoasting
source:
  - Windows 4769: A Kerberos service ticket was requested
last_updated: 2026-09-27
severity: high
confidence: medium
attack_simulation: impacket-GetUserSPNs (two-step via getTGT, AES256 negotiated in this lab)
notes: Classic RC4 filter (0x17) unreliable on modern DCs that negotiate AES by default. Volume-based detection on unique SPN requests used.
---

## Summary

Detects potential Kerberoasting by identifying accounts requesting TGS tickets for multiple service SPNs in a short time window. Surfaces both RC4 and AES encrypted requests, since modern DCs negotiate AES by default and the classic RC4 filter misses those.

## Why this matters

Kerberoasting lets any authenticated domain user request TGS tickets for accounts with SPNs, then crack those tickets offline to recover the service account password. No special privileges needed, no LSASS access, no noise on the target machine. The entire attack happens over legitimate Kerberos protocol.

Once cracked, service account passwords are often reused, never rotated, and frequently over-privileged. In this lab, svc-sql had DS-Replication rights, meaning Kerberoasting it was a direct path to DCSync.

4769 fires on every TGS request in the domain making it extremely noisy unfiltered. The detection filters out noise (krbtgt, computer account SPNs, failed requests) and summarizes by requesting account and time window to collapse attack bursts into single alerts.

## Signal logic

**Classic detection (unpatched environments):** filter on `TicketEncryptionType == 0x17` (RC4). Attackers request RC4 because it cracks faster than AES. On Server 2019/2022 without recent patches this is still the primary signal.

**Modern detection (AES environments):** an RC4 filter misses every request where AES was negotiated, which was the case for every Kerberoast in this lab. The encryption type depends on the target account's `msDS-SupportedEncryptionTypes` and the DC's defaults, not on the OS version alone. The same Server 2025 DC in this lab issued an RC4 AS-REP for j.schmidt (see AD-DET-003), so RC4 is still possible and still worth labeling. Volume-based detection instead: any account requesting TGS tickets for multiple distinct SPNs in a short window is suspicious. Normal users hit the same few services repeatedly. An attacker running GetUserSPNs hits every SPN in the domain at once.

`UniqueServices` uses `dcount` rather than raw event count to measure distinct SPNs targeted. This is more reliable since a user could legitimately generate many requests to the same service.

**Requester vs target filtering:** the two sides of a 4769 are filtered differently on purpose. On the target side (`ServiceName`), all computer accounts ending in `$` are excluded, because computer account passwords are random 120-character values that cannot realistically be cracked. Kerberoasting only pays off against user accounts with SPNs. On the requester side, only an explicit allowlist is excluded, so a compromised machine account doing Kerberoasting is still caught.

4769 logs the requester as `user@REALM` (for example `j.schmidt@LAB.LOCAL`). The query strips the realm into a `Requester` column before comparing it against the allowlist. Comparing the raw value silently never matches.

**Threshold tuning:** `UniqueServices >= 1` is used here because the lab only has one SPN. In production raise to 3-5 to reduce FP rate. Adjust the `bin` window from 5m to 1m in environments with many SPNs to tighten the burst detection.

`EncryptionTypes` in the output shows which encryption was negotiated, useful context for the analyst: RC4 means the hash is trivially crackable, AES means it's harder but not impossible.

False positives: legitimate service account automation that requests tickets for many services simultaneously. Applications doing service discovery via Kerberos. Raise the UniqueServices threshold and reduce the time window to tune. Background noise from krbtgt and computer account SPNs is removed on the target side. The `known_requesters` allowlist covers accounts that legitimately request many service tickets.

## KQL

```kusto
// Detection: Kerberoasting - Suspicious TGS Request Volume
// Event ID:  4769 - Kerberos service ticket requested
// MITRE:     T1558.003 - Kerberoasting
// Source:    SecurityEvent (Windows Security Log, DC only)
// Lab:       Telemetry confirmed in Sentinel workspace law-1 (lab.local)
//
// TUNING NOTES:
// 1. UniqueServices >= 1 is intentionally low for single-SPN lab environments.
//    In production raise to >= 3 or >= 5 to reduce FP rate.
// 2. Classic RC4 filter still valid where RC4 is negotiated. Add it as an
//    OR condition in mixed environments:
//    | where EncryptionTypes has "RC4" or UniqueServices >= 3
// 3. known_requesters: accounts that legitimately request many service
//    tickets (DC machine accounts, monitoring, service discovery).
//    Values are compared without the @REALM suffix, case-insensitive.
// 4. Computer account SPNs (ServiceName ending in $) are excluded as targets
//    because their passwords are not crackable. Requesters are NOT filtered
//    with !endswith "$", so compromised machine accounts are still caught.

let known_requesters = dynamic(["WIN-72DM6NS4BVH$"]);
SecurityEvent
| where EventID == 4769
| extend Status = extract(@'Status">([^<]+)', 1, EventData)
| where Status == "0x0"
| extend ServiceName = extract(@'ServiceName">([^<]+)', 1, EventData)
| where ServiceName !~ "krbtgt"
| where ServiceName !endswith "$"
| extend TargetUserName = extract(@'TargetUserName">([^<]+)', 1, EventData)
| extend Requester = tolower(tostring(split(TargetUserName, "@")[0]))
| where Requester !in~ (known_requesters)
| extend TicketEncryptionType = extract(@'TicketEncryptionType">([^<]+)', 1, EventData)
| extend IpAddress = extract(@'IpAddress">([^<]+)', 1, EventData)
| extend EncryptionLabel = case(
    TicketEncryptionType == "0x17", "RC4 - fast to crack",
    TicketEncryptionType == "0x12", "AES256 - slow to crack",
    TicketEncryptionType == "0x11", "AES128 - slow to crack",
    "Other"
)
| summarize
    RequestCount = count(),
    UniqueServices = dcount(ServiceName),
    ServiceList = make_set(ServiceName),
    EncryptionTypes = make_set(EncryptionLabel),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Requester, IpAddress, bin(TimeGenerated, 5m)
| where UniqueServices >= 1
| order by FirstSeen desc
```
