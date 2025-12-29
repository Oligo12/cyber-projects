# Incident Response Timeline - Legacy Sentinel Lab

## Incident Summary
- **Incident Type:** Malware infection leading to credential theft, command-and-control (C2), privilege escalation, and data exfiltration
- **Initial Vector:** Email phishing resulting in execution of a disguised batch file (`CompanyPolicy2025.pdf.bat`)
- **Initial Detection:** Registry-based persistence detection in Microsoft Sentinel
- **Severity:** Critical
- **Status:** Contained (lab simulation)

This incident was simulated in a controlled lab environment to demonstrate enterprise-style detection, investigation, and response workflows using Microsoft Sentinel.

---

## Environment Overview
- Hybrid SOC lab using Microsoft Sentinel
- On-prem Windows endpoints onboarded via Azure Arc
- Sysmon + Azure Monitor Agent (AMA) for endpoint telemetry
- Active Directory domain with cloud-hosted DC/DNS
- pfSense firewall and Suricata for network visibility
- Internal Linux VM acting as simulated attacker / C2 endpoint

(Full architecture and detection details are documented in [Legacy-Sentinel-Lab](,,/legacy-sentinel-lab/Legacy-Sentinel-Lab.pdf).)

---

## High-Level Attack Chain (Observed)

1. User executed a phishing attachment disguised as a PDF (`CompanyPolicy2025.pdf.bat`)
2. Script downloaded multiple payload components and established persistence
3. Reverse shell / C2 channel established via a renamed Netcat binary
4. Attacker performed local discovery and credential harvesting
5. Credentials and AD environment details were exfiltrated
6. Attacker accessed the AD Domain Controller via RDP
7. Privileges escalated to domain administrator
8. Additional sensitive data exfiltrated with elevated access

---

## Timeline of Events

### T0 - Initial Alert (Persistence Detection)
- Microsoft Sentinel triggered a **High severity** alert for **registry persistence**.
- Detection rule: `Persistence – Registry Run Key Modified`
- Registry value created:
  - Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - Value name: `HR_Update`
- Automated **Discord alert** notified the analyst.
- Affected host: `Sentinel-Win10.blue.lab`

---

### T1 - Triage
- Reviewed alert context and associated entities in Sentinel.
- Identified registry Run key configured to execute a suspicious script (`rat.vbs`) at user logon.
- Confirmed persistence was established immediately after execution of the phishing attachment.
- Activity was treated as a true positive based on execution context and persistence behavior.

---

### T2 - Investigation & Validation
- Correlated Sysmon telemetry:
  - File creation events following execution of the batch file
  - Registry modification events establishing persistence
  - Process creation events linked to script execution
- Identified multiple dropped components, including:
  - a renamed executable masquerading as a legitimate system binary
  - scripts responsible for execution chaining and beaconing
- Determined that the persistence mechanism triggered a script chain on reboot or logon.

---

### T3 - C2 / Beaconing Behavior Identified
- Observed repeated outbound connections at **30-second intervals**.
- Connections originated from the infected Windows host to an internal Linux VM.
- Analysis showed the beaconing behavior was implemented via:
  - execution of a renamed Netcat binary
  - launched through a persistent script chain
- Activity classified as **command-and-control (C2)** behavior.

---

### T4 - Discovery & Credential Exposure
- Over the established reverse shell, attacker executed discovery commands:
  - user and privilege enumeration
  - system and domain identification
- Sensitive files accessible to the compromised user were accessed.
- These files contained:
  - credentials and/or credential material
  - internal usernames
  - hostname and address information for the Active Directory Domain Controller
- Discovered data was **exfiltrated via the existing C2 channel**.

---

### T5 - Lateral Movement & Privilege Escalation
- Using exfiltrated credentials and AD information, attacker initiated access to the **Domain Controller via RDP**.
- Repeated authentication attempts were observed, consistent with **credential brute-force** behavior.
- Successful authentication achieved.
- Attacker elevated privileges for the account compromised during the initial access.

---

### T6 - Secondary Impact (Elevated Access Exfiltration)
- With administrative privileges, attacker accessed files restricted from the original compromised user.
- Additional **high-sensitivity data** was exfiltrated.
- Impact classified as **critical**, due to domain-wide compromise potential.

---

### T7 - Scope Assessment
- Queried Sentinel across all onboarded endpoints and servers for:
  - registry persistence artifacts
  - similar beaconing patterns
  - authentication failures followed by success
  - unauthorized account creation events
- No further compromised endpoints identified beyond the initial workstation and Domain Controller.

---

### T8 - Containment (Simulated)
- Compromised workstation and Domain Controller would be **isolated immediately**.
- Outbound communication to the identified C2 destination blocked at the firewall.
- Compromised user account administrative privileges revoked.
- Forced credential resets for affected users.

---

### T9 - Eradication
- Removed persistence mechanisms from the workstation.
- Deleted all dropped payload components.
- Removed unauthorized accounts and validated AD group memberships.
- Reviewed authentication and audit logs for residual attacker access.

---

### T10 - Recovery
- Systems would be restored to normal operation after validation.
- Domain-wide password resets and monitoring applied.
- Increased alerting for authentication anomalies and persistence techniques.

---

## Root Cause Analysis
- Initial compromise via phishing attachment disguised as a legitimate document.
- Persistence established via Windows Registry Run key.
- Reverse shell provided interactive access for discovery and credential theft.
- Poor credential hygiene and credential exposure on endpoints enabled escalation.
- Lack of early containment allowed attacker to progress to domain-level compromise.

---

## Lessons Learned & Improvements
- Strengthen detections for registry-based persistence and script execution chains.
- Improve alerting on repeated authentication failures and RDP access to critical systems.
- Monitor for unauthorized account creation and privilege changes in AD.
- Reduce credential exposure on endpoints.
- Enforce least privilege and stronger administrative access controls.
- Improve outbound egress filtering and correlation between persistence and network alerts.

---

## Analyst Notes
- This incident was intentionally simulated for blue-team training purposes.
- The scenario demonstrates how an initial endpoint compromise can escalate to full domain compromise if not rapidly contained.
- Early detection of persistence combined with aggressive containment is critical to preventing lateral movement and privilege escalation.
