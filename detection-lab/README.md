# Detection Lab: Microsoft Sentinel detections + response
**Author:** Nikola Marković  
**Status:** ongoing  
**Last updated:** 2026-09-27  
**Repo:** https://github.com/Oligo12/cyber-projects/  
**Email:** nikola.z.markovic@pm.me  
**LinkedIn:** https://www.linkedin.com/in/nikolazmarkovic/  

[Back to Main README](../README.md)

## Summary
Microsoft Sentinel lab covering two areas:

- **AD identity attacks:** a small Active Directory domain attacked from Kali with six common techniques (password spray, Kerberoasting, AS-REP roasting, DCSync, privileged group addition, GPO modification). Each attack has a KQL detection validated against the lab's own telemetry, with log samples and documented blind spots.
- **Malware behavior + response:** KQL detections built from behaviors observed in my malware analyses, plus a Sentinel playbook -> secure webhook -> Velociraptor API workflow that terminates a target PID on alert.

## Notes
- Lab-only learning and prototype content.
- This is a long-term lab and will be updated as I advance.
- Paths in this README are **relative** to this folder.

## What's here
- **[detections/](detections):** all KQL detections, with an index table.
  - **[ad-identity/](detections/ad-identity):** 6 AD attack detections (AD-DET-001 to 006).
  - **[malware/](detections/malware):** 7 behavior detections from malware analysis.
- **[log-samples/](log-samples):** query output from the lab for each AD detection.
- **[playbooks/](playbooks):** kill-by-pid response playbook and evidence of it working.
- **images/:** images used in this section of the repo.

## Status
- AD identity: 6 detections written and validated against lab attacks.
- Response: kill-by-pid playbook wired.
- Next: Okta and Entra ID identity detections, including an on-prem AD -> Entra pivot; memory dump and collection playbooks.

---

# AD identity detections

## Lab environment
| Host | Role | Appears in logs as |
|---|---|---|
| DC01 | Domain controller for `lab.local` (Windows Server 2025) | `WIN-72DM6NS4BVH` / `WIN-72DM6NS4BVH$` |
| CLIENT01 | Domain-joined workstation | Not involved in the attack chain, so no events in the log samples |
| Kali | Attacker | `10.10.10.50`, or `::ffff:10.10.10.50` in Kerberos events |

**Telemetry:** Advanced Audit Policy, Sysmon and command-line process auditing, deployed domain-wide via GPO. Events are shipped through Azure Arc + AMA + Data Collection Rules to Log Analytics workspace `law-1` and queried in Sentinel.

## Attack chain
| Step | Attack | Tool | Detection |
|---|---|---|---|
| 1 | Password spray recovers j.schmidt's password | nxc, kerbrute | [AD-DET-001](detections/ad-identity/AD-DET-001_password-spray.md) |
| 2 | AS-REP roasting against j.schmidt (pre-auth disabled) | impacket-GetNPUsers | [AD-DET-003](detections/ad-identity/AD-DET-003_asrep-roasting.md) |
| 3 | Kerberoasting svc-sql with j.schmidt's credentials | impacket-GetUserSPNs | [AD-DET-002](detections/ad-identity/AD-DET-002_kerberoasting.md) |
| 4 | svc-sql holds replication rights: DCSync dumps all hashes | impacket-secretsdump | [AD-DET-004](detections/ad-identity/AD-DET-004_dcsync.md) |
| 5 | Account added to Domain Admins from a SYSTEM session | impacket-atexec | [AD-DET-005](detections/ad-identity/AD-DET-005_new-domain-admin.md) |
| 6 | GPO created and linked at the domain root | PowerShell (GroupPolicy module) | [AD-DET-006](detections/ad-identity/AD-DET-006_gpo-change.md) |

## Findings from validation
Every detection was run against the lab's own attack telemetry, and several first versions turned out to be wrong. The details are in each detection's "Lab finding" and "Limitations" notes. Highlights:

- **Kerberoasting on Server 2025 negotiated AES**, so the classic RC4 filter (`0x17`) would have missed every attack. The detection uses request volume per account instead.
- **kerbrute userenum only logs the wrong guesses.** Nonexistent usernames produce 4768 with Status 0x6; valid usernames leave no trace in the Security log.
- **4728 alone only covers Domain Admins.** Enterprise Admins logs 4756 and the builtin groups and DnsAdmins log 4732. Groups are matched by SID, so renamed or localized names (for example "Domänen-Admins") are still caught.
- **4662 has no source IP.** The DCSync detection recovers it by joining to the 4624 logon on the same logon ID, which resolves the dump to Kali.
- **The first password spray version misreported success** in two ways (an untimed join, and missing accounts that succeeded on the first try). Both were found in the lab data and fixed.

## Design notes
Detections query `SecurityEvent` directly rather than ASIM parsers. Five of the six rely on AD-specific fields (PreAuthType, replication GUIDs, gPLink) that no ASIM schema covers. Password spray is the one candidate for ASIM Authentication normalization, but the built-in Windows parser does not cover the Kerberos events (4768, 4771) the detection depends on.

---

# Malware detections + response

## Topology
This is a separate environment from the AD identity lab above.
![Lab topology](images/SentinelTopology.png)

- **VMs:** Windows detonation client(s), AD DC/DNS, Ubuntu (Velociraptor server + webhook), pfSense.
- **Cloud:** Azure Arc + AMA -> Log Analytics Workspace -> Microsoft Sentinel.
- **Ingress:** Cloudflare Tunnel -> `https://webhook.[domain]/` -> Flask webhook -> Velociraptor API.

**Key IPs/Ports:**
- Velociraptor UI/API: **`:8889` / `:8001`**
- Webhook: **`:9999`** (behind Cloudflare)
- Detonation VM: **`192.168.1.101`**
- Velociraptor Server: **`192.168.1.20`**
- Client ID (lab): **`C.[example]`**

**Webhook (Flask) essentials**
- Validates `X-Auth-Token`, basic input checks.
- Calls Velociraptor server API with local config.
- Returns JSON status to Sentinel.

![webhook journal](images/WebhookLogs.png)  
*Flask webhook received `POST /kill` from the playbook and returned **200** (timestamps shown). `127.0.0.1` appears because the tunnel/proxy forwards to the local Flask service on `:9999`.*

**Velociraptor artifacts (VQL)**
- **Used:** `Windows.Remediation.Process` (terminate by PID/name)
- **Planned:** `Generic.System.Pstree`, `Windows.Memory.ProcessDump`, `Windows.Remediation.Quarantine`

## Simplified data flow
1. Sysmon/Windows -> AMA -> Log Analytics -> Sentinel.
2. Analytics rule fires.
3. Logic App playbook -> HTTPS POST to webhook (`/kill`).
4. Webhook validates token -> calls **Velociraptor** (VQL artifact) against **client_id**.
5. Results/evidence saved back to lab.
