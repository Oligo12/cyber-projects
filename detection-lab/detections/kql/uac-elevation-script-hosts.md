```yaml
title: UAC elevation via script hosts (attempt + success)
status: prototype (PoC)
mitre: T1548.002 (Abuse Elevation Control Mechanism)
source:
  - Windows 4104: PowerShell ScriptBlock
  - Sysmon EID 1: ProcessCreate
  - Windows 4672: Special privileges assigned
last_updated: 2025-10-12
severity: high
confidence: medium
notes: Lab-oriented; detects explicit RunAs attempts and likely success via 4672 (SeDebug/SeTcb); minimal lab trims.
```
---

## Summary
Detects UAC elevation attempts (-Verb RunAs / runas) from common script hosts and likely success when a matching 4672 (with SeDebug or SeTcb) lands on the same host/user within ~1 minute.

## Why this matters
An elevated token enables persistence, credential access, and tampering with defenses. Surfacing both the intent and the token grant gives early, actionable visibility.

## Signal Logic
- **ps_runas_4104** - PowerShell 4104 content contains -Verb RunAs (attempt).
- **proc_runas_1** - Sysmon EID 1 script host with RunAs semantics in the command line (attempt).
- **script_to_4672** - Script host start followed by 4672 with SeDebug or SeTcb within elevationWindow (likely success).

---

## KQL
```kusto
let elevationWindow = 1m;
let script_hosts = dynamic([
  "powershell.exe","pwsh.exe","cmd.exe",
  "wscript.exe","cscript.exe","mshta.exe",
  "python.exe","node.exe","perl.exe","ruby.exe",
  "msbuild.exe","installutil.exe","regsvr32.exe","rundll32.exe",
  "wmic.exe","msxsl.exe","msiexec.exe","powershell_ise.exe",
  "runas.exe"
]);

// Lab-only suppressions (keep signal visible). In prod: use signer/reputation instead of regex-only.
let benign_cmd_patterns = dynamic([
  "\\\\Program Files\\\\AzureConnectedMachineAgent\\\\",
  "AzureMonitorAgentExtension\\.exe",
  "Microsoft\\.Azure\\.Monitor\\.AzureMonitorWindowsAgent",
  "azcmagent_check_updates\\.ps1",
  "SCHTASKS\\.EXE.*\\sazcmagent\\b",
  "Heartbeat\\.psm1",
  "Test-ChangeTrackingEnabled",
  "C:\\\\ProgramData\\\\GuestConfig\\\\downloads\\\\AzureWindowsBaseline\\\\pre_install\\.ps1",
  // Encoded: [Environment]::OSVersion.Version
  "-encodedCommand\\s+IABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBPAFMAVgBlAHIAcwBpAG8AbgAuAFYAZQByAHMAaQBvAG4AIAA=",
  "HKCU:\\\\Software\\\\Classes\\\\Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\BagMRU",
  "HKCU:\\\\Software\\\\Classes\\\\Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\Bags",
  "GroupView"
]);
let benign_parent_patterns = dynamic([
  "\\\\Program Files\\\\AzureConnectedMachineAgent\\\\",
  "AzureMonitorAgentExtension\\.exe",
  "Microsoft\\.Azure\\.Monitor\\.AzureMonitorWindowsAgent"
]);

let is_benign = (txt:string) { tolower(txt) matches regex strcat(@"(", strcat_array(benign_cmd_patterns, "|"), @")") };
let benign_parent = (pp:string) { tolower(pp) matches regex strcat(@"(", strcat_array(benign_parent_patterns, "|"), @")") };

// A1 - PowerShell ScriptBlock (4104) with explicit RunAs (content signal)
let A1_PS_RunAs_4104 =
    win_4104_powershell_scriptblock
    | where isnotempty(script_block_text)  
    | where tolower(script_block_text) contains "-verb runas"
    | where not(is_benign(script_block_text))
    | extend det_rule = "PS_UAC_Attempt_4104",
             user_coalesced = tostring(column_ifexists("user_name","")),
             evidence_coalesced = tostring(script_block_text);

// A2 - Sysmon EID 1: script host using RunAs semantics (process signal)
let A2_PS_RunAs_Sysmon =
    Sysmon_1_ProcessCreate()
    | extend proc_lc = tolower(process_name), cl = tolower(tostring(command_line))
    | where proc_lc in (script_hosts)
    | where cl contains "-verb runas"
      or (cl contains "start-process" and cl contains "-verb" and cl contains "runas")
      or cl contains "runas /user:"  
    | where not(is_benign(cl)) and not(benign_parent(parent_process_path))
    | extend det_rule = "PS_UAC_Attempt_Sysmon1",
             user_coalesced = tostring(column_ifexists("user_name","")),
             evidence_coalesced = tostring(column_ifexists("command_line",""));

// B - Correlation: script host (EID 1) -> 4672 (special privs) within elevationWindow
// Requires SeDebug OR SeTcb to reduce generic 4672 noise.
let B_ScriptHost_then_4672_base =
    Sysmon_1_ProcessCreate()
    | where tolower(process_name) in (script_hosts)
    | where not(is_benign(command_line)) and not(benign_parent(parent_process_path))
    | extend sh_time = time_generated,
             sh_user = tostring(column_ifexists("user_name","")),
             sh_proc = process_name,
             sh_cmd  = command_line;

let B_ScriptHost_then_4672 =
    B_ScriptHost_then_4672_base
    | join kind=inner (
        win_4672_special_privs
        | where has_sedebug or has_setcb
        | extend elev_time = time_generated, elev_user = subject_user_name
        | project-away time_generated
    ) on computer
    | where elev_time between (sh_time .. sh_time + elevationWindow)
      and (isempty(sh_user) or isempty(elev_user) or tolower(sh_user) == tolower(elev_user))
    | extend time_generated = sh_time,
             det_rule = "ScriptHost_then_4672",
             user_coalesced = tostring(column_ifexists("elev_user", sh_user)),
             evidence_coalesced = strcat(tostring(sh_proc),
                                         " -> 4672 within ",
                                         tostring(elevationWindow),
                                         " | cmd=", tostring(sh_cmd));

// Final Union Signals
A1_PS_RunAs_4104
| union A2_PS_RunAs_Sysmon
| union B_ScriptHost_then_4672
| where isempty(user_coalesced) or tolower(user_coalesced) !in ("system","administrator")
| project-reorder time_generated, computer, det_rule, user_coalesced, evidence_coalesced
| sort by time_generated desc
```
