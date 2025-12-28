```yaml
title: UAC elevation attempts via script hosts and LOLBins
status: prototype (PoC)
mitre: T1548.002 (Abuse Elevation Control Mechanism)
source:
  - Windows 4104: PowerShell ScriptBlock
  - Sysmon EID 1: ProcessCreate
  - Windows 4672: Special privileges assigned
last_updated: 2025-10-12
severity: high
confidence: medium
notes: Lab-oriented; detects explicit RunAs attempts and correlates them with nearby privileged logon signals (4672); does not assert confirmed elevation success.
```
---

## Summary
Detects **UAC elevation attempts** initiated via script hosts and common LOLBins (e.g., PowerShell, cmd, mshta, regsvr32) using explicit RunAs semantics. 
Also correlates these attempts with a **near-time privileged logon signal** (Windows 4672 with SeDebug or SeTcb) on the same host/user to highlight **potential elevation outcomes**. 
The rule surfaces both **intent** (RunAs usage) and **contextual privilege assignment**, providing early visibility into suspicious elevation activity without asserting guaranteed success.

## Why this matters
An elevated token enables persistence, credential access, and tampering with defenses. Surfacing both the intent and the token grant gives early, actionable visibility.

## Signal Logic
- **ps_runas_4104** - PowerShell 4104 content contains -Verb RunAs (attempt).
- **proc_runas_1** - Sysmon EID 1 script host with RunAs semantics in the command line (attempt).
- **script_to_4672** - Script host start followed by 4672 with SeDebug or SeTcb within elevationWindow (potential privileged logon correlation).

---

## KQL
```kusto
let elevationWindow = 1m;

// Script hosts + common LOLBins that can participate in elevation chains
let script_hosts = dynamic([
  "powershell.exe","pwsh.exe","powershell_ise.exe","cmd.exe",
  "wscript.exe","cscript.exe","mshta.exe",
  "python.exe","node.exe","perl.exe","ruby.exe",
  "msbuild.exe","installutil.exe","regsvr32.exe","rundll32.exe",
  "wmic.exe","msxsl.exe","msiexec.exe",
  "runas.exe"
]);

// Lab-only suppressions. In prod: use signer/reputation instead of regex-only.
let benign_cmd_patterns = dynamic([
  "\\\\program files\\\\azureconnectedmachineagent\\\\",
  "azuremonitoragentextension\\.exe",
  "microsoft\\.azure\\.monitor\\.azuremonitorwindowsagent",
  "azcmagent_check_updates\\.ps1",
  "schtasks\\.exe.*\\sazcmagent\\b",
  "heartbeat\\.psm1",
  "test-changetrackingenabled",
  "c:\\\\programdata\\\\guestconfig\\\\downloads\\\\azurewindowsbaseline\\\\pre_install\\.ps1",
  // Encoded: [Environment]::OSVersion.Version
  "-encodedcommand\\s+iabbaeuabgb2ag4abqblag4adabdaoaoagbpa...=", 
  "hkcu:\\\\software\\\\classes\\\\local settings\\\\software\\\\microsoft\\\\windows\\\\shell\\\\bagmru",
  "hkcu:\\\\software\\\\classes\\\\local settings\\\\software\\\\microsoft\\\\windows\\\\shell\\\\bags",
  "groupview"
]);

let benign_parent_patterns = dynamic([
  "\\\\program files\\\\azureconnectedmachineagent\\\\",
  "azuremonitoragentextension\\.exe",
  "microsoft\\.azure\\.monitor\\.azuremonitorwindowsagent"
]);

let is_benign = (txt:string) { tolower(tostring(txt)) matches regex strcat(@"(", strcat_array(benign_cmd_patterns, "|"), @")") };
let benign_parent = (pp:string) { tolower(tostring(pp)) matches regex strcat(@"(", strcat_array(benign_parent_patterns, "|"), @")") };

// A1 - PowerShell ScriptBlock (4104) with explicit RunAs (content signal)
let A1_PS_RunAs_4104 =
    win_4104_powershell_scriptblock
    | where isnotempty(script_block_text)
    | where tolower(script_block_text) contains "-verb runas"
    | where not(is_benign(script_block_text))
    | extend det_rule = "UAC_Attempt_4104_RunAs",
             user_coalesced = tostring(column_ifexists("user_name","")),
             evidence_coalesced = tostring(script_block_text);

// A2 - Sysmon EID 1: elevation semantics in command line (process signal)
let A2_UAC_Sysmon1 =
    Sysmon_1_ProcessCreate()
    | extend proc_lc = tolower(tostring(process_name)),
             cl      = tolower(tostring(command_line)),
             pp      = tolower(tostring(parent_process_path))
    | where proc_lc in (script_hosts)
    | where cl contains "-verb runas"
       or (cl contains "start-process" and cl contains "-verb" and cl contains "runas")
       or (proc_lc == "runas.exe" and cl contains "/user:")
    | where not(is_benign(cl)) and not(benign_parent(pp))
    | extend det_rule = "UAC_Attempt_Sysmon1",
             user_coalesced = tostring(column_ifexists("user_name","")),
             evidence_coalesced = tostring(column_ifexists("command_line",""));

// B - Correlation: script host / LOLBin (EID 1) -> 4672 (special privs) within elevationWindow
// Requires SeDebug OR SeTcb to reduce generic 4672 noise.
let B_Host_then_4672_base =
    Sysmon_1_ProcessCreate()
    | extend proc_lc = tolower(tostring(process_name)),
             cl      = tolower(tostring(command_line)),
             pp      = tolower(tostring(parent_process_path))
    | where proc_lc in (script_hosts)
    | where not(is_benign(cl)) and not(benign_parent(pp))
    | extend sh_time = time_generated,
             sh_user = tostring(column_ifexists("user_name","")),
             sh_proc = tostring(process_name),
             sh_cmd  = tostring(command_line);

let B_Host_then_4672 =
    B_Host_then_4672_base
    | join kind=inner (
        win_4672_special_privs
        | where has_sedebug or has_setcb
        | extend elev_time = time_generated,
                 elev_user = tostring(subject_user_name)
        | project elev_time, elev_user, computer
    ) on computer
    | where elev_time between (sh_time .. sh_time + elevationWindow)
      and (isempty(sh_user) or isempty(elev_user) or tolower(sh_user) == tolower(elev_user))
    | extend time_generated = sh_time,
             det_rule = "UAC_Signal_then_4672",
             user_coalesced = coalesce(elev_user, sh_user),
             evidence_coalesced = strcat(sh_proc, " -> 4672 within ", tostring(elevationWindow), " | cmd=", sh_cmd);

// Final Union Signals
A1_PS_RunAs_4104
| union A2_UAC_Sysmon1
| union B_Host_then_4672
| where isempty(user_coalesced) or tolower(user_coalesced) !in ("system","administrator")
| project-reorder time_generated, computer, det_rule, user_coalesced, evidence_coalesced
| sort by time_generated desc
```
