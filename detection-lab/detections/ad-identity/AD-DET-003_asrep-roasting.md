---
title: AS-REP Roasting - TGT Requested Without Pre-Authentication (4768)
status: lab prototype
mitre:
  - T1558.004: Steal or Forge Kerberos Tickets - AS-REP Roasting
source:
  - Windows 4768: A Kerberos authentication ticket (TGT) was requested
last_updated: 2026-09-27
severity: high
confidence: high
attack_simulation: impacket-GetNPUsers
notes: Core signal is PreAuthType=0 only. TicketEncryptionType is enrichment, not a filter - AES-based AS-REP roasting is caught too.
---

## Summary

Detects TGT requests where Kerberos pre-authentication was not required, indicating an account with "Do not require Kerberos preauthentication" enabled. Any such request from a non-localhost source is a likely AS-REP roasting attempt.

## Why this matters

Kerberos pre-authentication exists to prevent offline cracking. Without it, the DC issues a TGT encrypted with the target account's password hash to anyone who asks, no credentials needed.                                                                                 
The attacker takes that encrypted blob offline and cracks it, recovering the plaintext password.

The vulnerability is on the account, not the attacker. A single misconfigured account with pre-auth disabled exposes its credentials to any unauthenticated attacker who knows the username.                                                                                 
In this lab, j.schmidt had pre-auth disabled, a common real-world misconfiguration left in place for legacy application compatibility.

4768 fires on every TGT request, successful or failed, and only on Domain Controllers.                                                                                                                                                                                     
The vast majority are legitimate logons with PreAuthType=2 (encrypted timestamp pre-auth). PreAuthType=0 is the anomaly.

## Signal logic

**PreAuthType=0** is the entire detection signal. It means the DC issued a TGT without requiring the client to prove knowledge of the password first. Password-based TGT requests normally use PreAuthType=2. Smartcard (PKINIT) and FAST logons use other values such as 15, 16, 17 or 138, which are not suspicious by themselves. Only 0 means no pre-authentication happened at all.

**TicketEncryptionType** is enrichment only, not a filter. AS-REP roasting works with both RC4 (`0x17`) and AES (`0x11`, `0x12`). RC4 hashes crack significantly faster offline, AES is harder but not impossible. The `CrackDifficulty` field surfaces this immediately so the analyst can prioritize response.

**IpAddress** identifies the requesting client. In this lab, Kali's IP `10.10.10.50` appears in IPv4-mapped IPv6 format as `::ffff:10.10.10.50`, which is how Windows logs IPv4 addresses in Kerberos events. `::1` is localhost, which fired when pre-auth was configured directly on DC01.

4768 fields are not parsed into named Sentinel columns. All fields require `extract()` from the raw XML EventData. The `PreAuthType` extract runs first so the filter eliminates non-zero rows before the remaining extracts run.

False positives: the detection is accurate every time it fires since PreAuthType=0 always means pre-auth is genuinely disabled on that account. The triage question is whether that condition is intentional. Pre-auth gets disabled for legacy applications that cannot do encrypted timestamp auth, or more commonly through misconfiguration while troubleshooting auth issues. If a known account has pre-auth disabled for a legitimate reason, document it as accepted risk rather than suppressing the detection. You still want to know when someone requests a TGT for that account without pre-auth even if the condition is known. Localhost `::1` events can be suppressed if DC-local tooling generates them regularly.

## KQL

```kusto
// Detection: AS-REP Roasting - TGT Without Pre-Authentication
// Event ID:  4768 - Kerberos TGT requested
// MITRE:     T1558.004 - AS-REP Roasting
// Source:    SecurityEvent (Windows Security Log, DC only)
// Lab:       Telemetry confirmed in Sentinel workspace law-1 (lab.local)
//
// TUNING NOTES:
// 1. PreAuthType=0 is the core signal. Do NOT add a TicketEncryptionType filter
//    as that would miss AES-based AS-REP roasting.
// 2. To suppress DC-local noise, add: | where IpAddress != "::1"
// 3. In production, any account triggering this should be reviewed for whether
//    pre-auth disabled is actually required, and if not, re-enable it immediately.

SecurityEvent
| where EventID == 4768
| extend PreAuthType = extract(@'PreAuthType">([^<]+)', 1, EventData)
| where PreAuthType == "0"
| extend TargetUserName = extract(@'TargetUserName">([^<]+)', 1, EventData)
| extend TicketEncryptionType = extract(@'TicketEncryptionType">([^<]+)', 1, EventData)
| extend IpAddress = extract(@'IpAddress">([^<]+)', 1, EventData)
| extend CrackDifficulty = case(
    TicketEncryptionType == "0x17", "RC4 - fast to crack",
    TicketEncryptionType == "0x11", "AES128 - slow to crack",
    TicketEncryptionType == "0x12", "AES256 - slow to crack",
    "Unknown"
)
| project TimeGenerated, Computer, TargetUserName, PreAuthType,
          TicketEncryptionType, CrackDifficulty, IpAddress
| order by TimeGenerated desc
```
