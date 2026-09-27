# Detections
[Back to Detection Lab](../README.md)

All detections are KQL for Microsoft Sentinel. Each file contains frontmatter (MITRE mapping, sources, severity, confidence), the reasoning behind the logic, false positives, and the query.

## AD identity
Validated against attacks from Kali in the lab domain. Log samples for each detection are in [log-samples/](../log-samples).

| ID | Detection | MITRE | Event IDs | Severity |
|---|---|---|---|---|
| [AD-DET-001](ad-identity/AD-DET-001_password-spray.md) | Password spray | T1110.003 | 4625, 4771, 4768 | Medium (high if succeeded) |
| [AD-DET-002](ad-identity/AD-DET-002_kerberoasting.md) | Kerberoasting | T1558.003 | 4769 | High |
| [AD-DET-003](ad-identity/AD-DET-003_asrep-roasting.md) | AS-REP roasting | T1558.004 | 4768 | High |
| [AD-DET-004](ad-identity/AD-DET-004_dcsync.md) | DCSync | T1003.006 | 4662, 4624 | High |
| [AD-DET-005](ad-identity/AD-DET-005_new-domain-admin.md) | Privileged group membership addition | T1098.007 | 4728, 4732, 4756 | High |
| [AD-DET-006](ad-identity/AD-DET-006_gpo-change.md) | GPO linking or modification | T1484.001 | 5136 | High |

## Malware behavior
Built from behaviors observed in my malware analyses.

| Detection | MITRE | Sources | Severity |
|---|---|---|---|
| [AppData-Local first-seen EXE](malware/appdata-local-new-exe.md) | T1204 | Sysmon 11, 1 | Medium |
| [Startup-folder persistence](malware/startup-persistence.md) | T1547.001 | Sysmon 11, 1 | Medium |
| [UAC elevation via script hosts and LOLBins](malware/uac-elevation-script-hosts-lolbins.md) | T1548.002 | 4104, Sysmon 1, 4672 | High |
| [User-writable parent -> AppData/Temp drop](malware/user-writable-parent-to-temp-appdata.md) | T1204 | Sysmon 1, 11 | Medium |
| [WMI event subscription persistence](malware/wmi-event-subscription-persistence-chain.md) | T1546.003 | Sysmon 19, 20, 21 | High |
| [Delayed execution + respawn loop](malware/delayed_command_execution_respawn_loop.md) | T1059, T1497.003, T1070 | Sysmon 1, 5 | Medium-high |
| [PowerShell in-memory loader (score-based)](malware/powerShell_in-memory_loader_behavior.md) | T1059.001, T1027, T1620 | 4104 | High |
