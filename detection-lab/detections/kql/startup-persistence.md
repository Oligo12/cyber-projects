```yaml
title: Startup-folder persistence (drop OR execute) 
status: prototype (PoC)
mitre: T1547.001   
source:
  - Sysmon EID 11: FileCreate
  - Sysmon EID 1: ProcessCreate   
last_updated: 2025-10-11     
severity: medium
confidence: medium      
notes: Prototype with minimal lab trims.
```
---

## Summary
Detects creation **or** execution of scriptable items and shortcuts in **Startup** folders (per-user & all-users). Good early-signal for simple persistence and LOLBins.

## Why this matters
Attackers abuse the Startup folders to auto-run scripts/shortcuts at logon. Catching the **drop** + **exec** signals gives both setup and use of persistence.

## Signal logic
- **startup_drop** - New script/shortcut created in a Startup path (e.g., `.vbs`, `.ps1`, `.lnk`, `.url`).
- **startup_exec** - Script/host interpreters (wscript/cscript/powershell/mshta/cmd/rundll32/java) launching a script **or** referencing a Startup path.
- **startup_exec_explorer** - Explorer-launched processes within ~2m of Explorer start (typical for .lnk at logon).
  
---

## KQL
```kusto
// EXEC via Explorer (.lnk at logon)
let explorer_start =
    Sysmon_1_ProcessCreate()
    | extend proc_lc = tolower(tostring(process_path)),
             comp_s  = tostring(computer),
             user_s  = tostring(user_name)
    | where proc_lc matches regex @"\\explorer\.exe$"
    | summarize explorer_start = max(time_generated) by comp_s, user_s;

let s_exec_explorer =
    Sysmon_1_ProcessCreate()
    | extend parent_lc = tolower(tostring(parent_process_name)),
             path_lc   = tolower(tostring(process_path)),
             cmd_lc    = tolower(tostring(command_line)),
             comp_s    = tostring(computer),
             user_s    = tostring(user_name)
    | where parent_lc == "explorer.exe"
    | join kind=leftouter (explorer_start) on comp_s, user_s
    | where isnotempty(explorer_start)
    | where time_generated between (explorer_start .. explorer_start + 2m)
    // trims
    | where not( path_lc matches regex @"\\system32\\taskmgr\.exe$" )
    | where not( path_lc has @"\microsoft\edge\application\msedge.exe"
                 and cmd_lc has_any ("--no-startup-window","--win-session-start") )
    | extend detection = "startup_exec_explorer"
    | project time_generated,
              computer   = comp_s,
              user_name  = user_s,
              detection, process_id, process_path, command_line, parent_process_name;


// DROP signal: suspicious file created in per-user or all-users Startup
let s_drop =
    Sysmon_11_FileCreate()
    | where isnotempty(target_filename)
    | extend target_lc = tolower(target_filename), ext = tolower(file_ext)
    | where target_lc has @"\microsoft\windows\start menu\programs\startup\"
        or target_lc has @"\programdata\microsoft\windows\start menu\programs\startup\"
    | where ext in ("vbs","vbe","js","jse","wsf","wsh","hta","ps1","bat","cmd","lnk","scr","url")
    | extend detection   = "startup_drop",
             b_user_name = user_name,
             comp_s        = tostring(computer),
             process_guid_s = tostring(process_guid) 
    | where isnotempty(process_guid_s)
    | project time_generated, comp_s, b_user_name, detection,
              process_id, process_path, target_filename, file_ext, process_guid_s;


let p1 =
    Sysmon_1_ProcessCreate()
| extend comp_s = tostring(computer),
         process_guid_s = tostring(process_guid)
| where isnotempty(process_guid_s)
| summarize arg_max(time_generated, *) by comp_s, process_guid_s
| project comp_s, process_guid_s, parent_process_name, parent_process_path;

let s_drop_parent =
    s_drop
    | join kind=leftouter p1 on comp_s, process_guid_s
    | project time_generated,
              computer = comp_s,
              b_user_name, detection,
              process_id, process_path,
              parent_process_name, parent_process_path,
              target_filename, file_ext;

// EXEC signal: interpreters launching scripts or items from Startup
let s_exec =
    Sysmon_1_ProcessCreate()
    | extend proc_lc = tolower(tostring(process_path)), cmd_lc = tolower(tostring(command_line))
    // Common script/host interpreters
    | where proc_lc matches regex @"\\(w|c)script\.exe$"
        or proc_lc matches regex @"\\powershell(?:\.exe)?$"
        or proc_lc matches regex @"\\cmd\.exe$"
        or proc_lc matches regex @"\\mshta\.exe$"
        or proc_lc matches regex @"\\rundll32\.exe$"
        or proc_lc matches regex @"\\javaw?\.exe$"
    // Evidence of script path or Startup path on the cmdline
    | where cmd_lc has_any (".vbs",".vbe",".ps1",".js",".jse",".wsf",".wsh",".hta",".bat",".cmd",".lnk",".scr",".url")
        or cmd_lc has @"\microsoft\windows\start menu\programs\startup\"
        or cmd_lc has @"\programdata\microsoft\windows\start menu\programs\startup\"
    // Typical installer/updater noise (expand with signer/parent checks)
    | where not(cmd_lc contains "azcmagent" 
        or cmd_lc contains "check_updates.ps1"
        or cmd_lc has @"\programdata\guestconfig\downloads\azurewindowsbaseline\")
    | where tolower(parent_process_name) !in ("msiexec.exe","setup.exe","gc_arc_service.exe")
    // Known benign GoogleUpdater uninstall flow
    | where not( cmd_lc has @"\program files (x86)\google\googleupdater\" and cmd_lc has "uninstall.cmd" )
    | extend a_user_name = user_name
    | extend detection = "startup_exec"
    | project time_generated, computer, a_user_name, detection,
              process_id, process_path, command_line, parent_process_name;

// Fire if either signal appears
union s_drop_parent, s_exec, s_exec_explorer
| order by time_generated desc
| extend user_name = coalesce(a_user_name, b_user_name, user_name)
| project-away a_user_name, b_user_name
```
