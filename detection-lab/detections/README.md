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

## Okta identity
Validated against attacks simulated from a browser over VPN in a free Okta Integrator tenant. Log samples for each detection are in [log-samples/](../log-samples).

| ID | Detection | MITRE | Event types | Severity |
|---|---|---|---|---|
| [OKTA-DET-001](okta-identity/OKTA-DET-001_password-spray.md) | Password spray | T1110.003 | user.session.start, user.authentication.auth_via_mfa | Medium (high if succeeded) |
| [OKTA-DET-002](okta-identity/OKTA-DET-002_mfa-fatigue.md) | MFA fatigue (push bombing) | T1621 | system.push.send_factor_verify_push, user.authentication.auth_via_mfa | Medium (high if approved) |
| [OKTA-DET-003](okta-identity/OKTA-DET-003_new-admin.md) | New admin role grant | T1098.003 | user.account.privilege.grant, group.privilege.grant | Medium (high if super/org admin) |
| [OKTA-DET-004](okta-identity/OKTA-DET-004_policy-tampering.md) | Policy tampering shortly after admin grant | T1556.009 | policy.lifecycle.*, policy.rule.*, user.account.privilege.grant | Medium (high if recent admin) |

## Entra ID identity
Validated against attacks simulated through the Entra admin center and Microsoft Graph PowerShell in a free Entra ID tenant. Log samples for each detection are in [log-samples/](../log-samples).

| ID | Detection | MITRE | Operations | Severity |
|---|---|---|---|---|
| [ENTRA-DET-001](entra-identity/ENTRA-DET-001_privileged-role.md) | Privileged directory role assignment | T1098.003 | Add member to role, Add eligible member to role | Medium (high if privileged role) |
| [ENTRA-DET-002](entra-identity/ENTRA-DET-002_app-credential.md) | Credential added to app or service principal | T1098.001 | Update application – Certificates and secrets management, Add service principal credentials | High (medium if same actor created the app recently) |
| [ENTRA-DET-003](entra-identity/ENTRA-DET-003_consent-grant.md) | OAuth permission grant with high-risk scopes | T1528, T1098.003 | Consent to application, Add delegated permission grant, Add app role assignment to service principal | Medium (high if risky scopes) |

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
