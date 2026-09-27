---
title: Password Spray - Failed Logon Burst Across Multiple Accounts (4625/4771/4768)
status: lab prototype
mitre:
  - T1110.003: Brute Force Password Spraying
source:
  - Windows 4625: An account failed to log on (NTLM)
  - Windows 4771: Kerberos pre-authentication failed
  - Windows 4768: Kerberos TGT requested (Status 0x6 = unknown username)
last_updated: 2026-09-27
severity: medium
confidence: medium
attack_simulation: nxc smb (NTLM/4625) + kerbrute passwordspray (Kerberos/4771) + kerbrute userenum (Kerberos/4768 0x6)
notes: SpraySucceeded=true elevates severity to high. UniqueAccounts threshold needs tuning per environment size. All three branches confirmed in this lab - nxc smb generated 4625 (NTLM), kerbrute passwordspray generated 4771, kerbrute userenum generated 4768 0x6 (Kerberos).
---

## Summary

Detects password spray attempts by identifying bursts of failed logons from a single source IP across multiple distinct accounts in a short time window. Combines NTLM (4625) and Kerberos (4771, 4768) failures, enriches with account validity, and joins against successful logons to determine whether the spray worked.

## Why this matters

Password spraying tries one or a few passwords against many accounts to avoid lockout thresholds. It's one of the most common initial access techniques because it requires no prior knowledge beyond a username list, and most environments have at least some accounts with weak or default passwords.

Unlike brute force against a single account, spray is designed to stay under lockout thresholds by distributing attempts across many accounts. This means individual account-level monitoring misses it entirely. Detection requires aggregating failures by source IP across accounts.

In this lab, a single spray run with nxc recovered j.schmidt:P@ssw0rd123, which was then used for Kerberoasting and ultimately DCSync. Spray was the initial foothold for the attack chain.

## Signal logic

**Three event sources:** 4625 covers NTLM-based failures (SMB, LDAP, most spray tools by default). 4771 covers Kerberos pre-authentication failures (wrong password). 4768 with Status 0x6 covers Kerberos requests for usernames that do not exist. All three are unioned into a normalized stream so spray attempts using either protocol are caught. In this lab nxc generated 4625, kerbrute passwordspray generated 4771 and kerbrute userenum generated 4768 0x6, so all three branches are confirmed.

**SubStatus codes for 4625:** only two are relevant for spray detection. `0xC000006A` means correct username, wrong password, confirming the account exists. `0xC0000064` means the username does not exist. Both are included because enumerating valid usernames is part of the spray workflow. Other failure codes (locked out, workstation restriction, expired password) are excluded as they are not password failures.

**UniqueAccounts over FailureCount:** spray has a distinct shape from brute force. Brute force is many attempts against one account. Spray is few attempts against many accounts. `dcount(TargetUserName)` per source IP directly measures this shape. Raw failure count would flag a single locked-out account just as loudly as a spray run.
  
**ValidAccounts vs NonExistentAccounts:** `make_set_if` separates confirmed valid usernames (SubStatus `0xC000006A`) from nonexistent ones (`0xC0000064`). This tells the analyst which accounts are at risk even before checking for successful logons.  

**Username enumeration blind spot:** kerbrute userenum sends TGT requests without pre-authentication. For nonexistent names the DC logs 4768 with Status 0x6, which this detection counts as nonexistent accounts. For names that exist, the DC replies "pre-authentication required", which is not logged, since it is a normal step of every Kerberos logon. An attacker's enumeration therefore shows up as a list of wrong guesses, while the confirmed valid usernames leave no trace. A burst containing only nonexistent accounts indicates enumeration rather than a spray.

**Successful logon correlation:** spray results are joined against successful logons from the same source IP: 4624 LogonType 3 for NTLM and 4768 with Status 0x0 for Kerberos. Only successes between the first failure and one hour after the last failure count, so an unrelated logon from the same IP days later does not mark the spray as successful. AS-REP requests (PreAuthType 0) are excluded from the Kerberos side since they return a ticket without proving the password.

`SpraySucceeded` is true in two cases. First, an account that failed during the spray logs in successfully from the same source within one hour (`AttemptedAccounts` intersected with `SuccessfulLogons`). Second, any account logs in successfully from the spray source during the burst itself, plus or minus one minute (`BurstSuccesses`). The second case is needed because an account whose password is correct on the first try never fails, so it never appears in `AttemptedAccounts`. A true value should immediately elevate the incident priority. Note that `SpraySucceeded` means an account logged in successfully from the spray source; it does not prove the spray itself found the password. In this lab, svc-sql appears in `SuccessfulLogons` for the 26.09 spray because it logged in from Kali shortly after, using a password recovered through Kerberoasting, not through the spray. For triage that distinction does not matter: the account is compromised either way.

**Case normalization:** usernames are lowercased in every branch. Windows logs the same account as `Administrator` or `administrator` depending on what the client sent, and both `dcount` and `set_intersect` are case-sensitive.

**Lab finding:** the first version of this query joined against all 4624s from the source IP over two days with no time bound. That falsely marked a failed kerbrute run as successful because nxc had logged in successfully from the same IP earlier. The time-bounded join fixes this. A second gap was found in review: in the kerbrute passwordspray runs, j.schmidt and a.mueller logged in from Kali during the spray, but SpraySucceeded stayed false, because both passwords were correct on the first attempt and the accounts never appeared among the failures. The BurstSuccesses check fixes this.

**Localhost and empty IP exclusion:** `::1` and `-` are excluded from the IP filter since they represent local auth events unrelated to network spray.

False positives: vulnerability scanners and monitoring tools that authenticate to many hosts. IT admin scripts doing bulk credential validation. Raise `UniqueAccounts` threshold to 5-10 in active environments. Add a source IP allowlist for known scanning infrastructure. In environments with many service accounts doing scheduled auth, exclude known service account source IPs.

## KQL

```kusto
// Detection: Password Spray - Failed Logon Burst
// Event IDs: 4625 (NTLM failure), 4771 (Kerberos pre-auth failure),
//            4768 Status 0x6 (Kerberos unknown username)
//            4624, 4768 Status 0x0 (success correlation)
// MITRE:     T1110.003 - Password Spraying
// Source:    SecurityEvent (Windows Security Log, DC and member servers)
// Lab:       Telemetry confirmed in Sentinel workspace law-1 (lab.local)
//
// TUNING NOTES:
// 1. UniqueAccounts >= 3 is intentionally low for lab environment.
//    Raise to >= 5 or >= 10 in production to reduce FP rate.
// 2. bin(TimeGenerated, 5m) controls the detection window. Tighten to 1m
//    for faster detection, widen to 15m to catch slow sprays. Fixed bins can
//    split one spray run across two rows if it crosses a bin boundary.
// 3. Add known scanner/monitoring IPs to an exclusion list:
//    | where IpAddress !in (known_scanner_ips)
// 4. SpraySucceeded=true should trigger a higher severity alert or
//    automatic escalation. Consider splitting into two separate rules:
//    one for spray attempts (medium) and one for confirmed spray success (high).
// 5. SubStatus casing differs between OS versions (0xC000006A vs 0xc000006a).
//    in~ and =~ are case-insensitive, so both are covered.
// 6. A success counts only if it falls between the first failure and 1h after
//    the last failure. Widen the 1h if slow sprays are expected.
//
// --- Failed logons: NTLM ---
let failed_ntlm = SecurityEvent
| where EventID == 4625
| where LogonType == 3
| extend SubStatus = tostring(SubStatus)
| where SubStatus in~ ("0xc000006a", "0xc0000064")
| extend AccountValidity = case(
    SubStatus =~ "0xc000006a", "valid_account",
    SubStatus =~ "0xc0000064", "nonexistent_account",
    "unknown"
)
| extend TargetUserName = tolower(TargetUserName)
| project TimeGenerated, TargetUserName, IpAddress, EventID, AccountValidity;
// --- Failed logons: Kerberos wrong password ---
let failed_krb = SecurityEvent
| where EventID == 4771
| extend Status = extract(@'Status">([^<]+)', 1, EventData)
| where Status == "0x18"
| extend TargetUserName = tolower(extract(@'TargetUserName">([^<]+)', 1, EventData))
| extend IpAddress = extract(@'IpAddress">([^<]+)', 1, EventData)
| extend AccountValidity = "valid_account"
| project TimeGenerated, TargetUserName, IpAddress, EventID, AccountValidity;
// --- Failed logons: Kerberos unknown username ---
let failed_krb_unknown = SecurityEvent
| where EventID == 4768
| extend Status = extract(@'Status">([^<]+)', 1, EventData)
| where Status == "0x6"   // KDC_ERR_C_PRINCIPAL_UNKNOWN - username does not exist
| extend TargetUserName = tolower(extract(@'TargetUserName">([^<]+)', 1, EventData))
| extend IpAddress = extract(@'IpAddress">([^<]+)', 1, EventData)
| extend AccountValidity = "nonexistent_account"
| project TimeGenerated, TargetUserName, IpAddress, EventID, AccountValidity;
// --- Aggregate failures into spray windows ---
let spray = union failed_ntlm, failed_krb, failed_krb_unknown
| where IpAddress !in ("::1", "-", "")
| extend IpAddress = replace_string(IpAddress, "::ffff:", "")  // normalize IPv6-mapped IPv4 so all branches merge correctly
| summarize
    FailureCount = count(),
    UniqueAccounts = dcount(TargetUserName),
    AttemptedAccounts = make_set(TargetUserName),
    ValidAccounts = make_set_if(TargetUserName, AccountValidity == "valid_account"),
    NonExistentAccounts = make_set_if(TargetUserName, AccountValidity == "nonexistent_account"),
    EventTypes = make_set(EventID),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IpAddress, bin(TimeGenerated, 5m)
| where UniqueAccounts >= 3;
// --- Successful logons: NTLM ---
let success_ntlm = SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where TargetUserName !in~ ("ANONYMOUS LOGON", "-")
| project SuccessTime = TimeGenerated,
          IpAddress = replace_string(IpAddress, "::ffff:", ""),
          SuccessUser = tolower(TargetUserName);
// --- Successful logons: Kerberos ---
let success_krb = SecurityEvent
| where EventID == 4768
| extend Status = extract(@'Status">([^<]+)', 1, EventData)
| extend PreAuthType = extract(@'PreAuthType">([^<]+)', 1, EventData)
| where Status == "0x0"
| where PreAuthType != "0"   // AS-REP requests return a ticket without proving the password
| project SuccessTime = TimeGenerated,
          IpAddress = replace_string(extract(@'IpAddress">([^<]+)', 1, EventData), "::ffff:", ""),
          SuccessUser = tolower(extract(@'TargetUserName">([^<]+)', 1, EventData));
// --- Correlate spray windows with successes ---
spray
| join kind=leftouter (union success_ntlm, success_krb) on IpAddress
| extend InWindow = SuccessTime between (FirstSeen .. (LastSeen + 1h)),
         InBurst  = SuccessTime between ((FirstSeen - 1m) .. (LastSeen + 1m))
| summarize
    SuccessfulLogons = make_set_if(SuccessUser, InWindow),
    BurstSuccesses   = make_set_if(SuccessUser, InBurst),
    take_any(FailureCount, UniqueAccounts, AttemptedAccounts, ValidAccounts,
             NonExistentAccounts, EventTypes)
    by IpAddress, TimeGenerated, FirstSeen, LastSeen
| extend SpraySucceeded = array_length(set_intersect(AttemptedAccounts, SuccessfulLogons)) > 0
                       or array_length(BurstSuccesses) > 0
| project TimeGenerated, IpAddress, FirstSeen, LastSeen, FailureCount, UniqueAccounts,
          AttemptedAccounts, ValidAccounts, NonExistentAccounts, SuccessfulLogons,
          BurstSuccesses, SpraySucceeded, EventTypes
| order by FirstSeen desc
```
