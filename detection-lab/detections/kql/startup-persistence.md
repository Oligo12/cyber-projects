```yaml
title: Startup-folder persistence (drop OR execute) 
status: prototype (PoC)
mitre: T1547.001 (Boot or Logon Autostart Execution)
source:
  - Sysmon EID 11: FileCreate
  - Sysmon EID 1: ProcessCreate   
last_updated: 2025-10-11     
severity: medium
confidence: medium      
notes: Detects file drops and interpreter-based execution from Startup folders. Lab trims; convert to signer/path/reputation allowlists for prod.
```
---

## Summary
Detects creation **or** interpreter-based execution of scriptable items and shortcuts in **Startup** folders (per-user & all-users). 
Provides an early signal for simple persistence mechanisms commonly abused by malware and LOLBins.

## Why this matters
Attackers abuse the Startup folders to auto-run scripts/shortcuts at logon. Catching the **drop** + **exec** signals gives both setup and use of persistence.

## Signal logic
- **startup_drop** - New script/shortcut created in a Startup path (e.g., `.vbs`, `.ps1`, `.lnk`, `.url`).
- **startup_exec** - Script/host interpreters (wscript/cscript/powershell/mshta/cmd/rundll32/java) launching a script **or** referencing a Startup path.
- 
---

## KQL
```kusto
// DROP signal: suspicious file created in the per-user Startup folder (scripts/shortcuts + guarded .exe)
let s_drop =
    Sysmon_11_FileCreate()
    | where isnotempty(target_filename)
    | extend target_lc = tolower(tostring(target_filename)),
             ext       = tolower(tostring(file_ext)),
             proc_lc   = tolower(tostring(process_path))
    | where target_lc has @"\microsoft\windows\start menu\programs\startup\"
        or target_lc has @"\programdata\microsoft\windows\start menu\programs\startup\"
    | where ext in ("vbs","vbe","js","jse","wsf","wsh","hta","ps1","bat","cmd","lnk","scr", "url", "exe")
    // Reduce noise for .exe drops: focus on likely-abuse cases (creator from user-writable / odd locations)
    | where (ext != "exe") or (ext == "exe" and (
          proc_lc has @"\users\"
       or proc_lc has @"\appdata\"
       or proc_lc has @"\temp\"
       or proc_lc has @"\programdata\"
    ))
    | extend detection = "startup_drop",
             b_user_name = user_name
    | project time_generated, computer, b_user_name, detection,
              process_id, process_path, target_filename, file_ext;

// EXEC signal: interpreters launching items FROM Startup
let s_exec =
    Sysmon_1_ProcessCreate()
    | extend proc_lc = tolower(tostring(process_path)),
             cmd_lc  = tolower(tostring(command_line))
    // Common script/host interpreters
    | where proc_lc matches regex @"\\(w|c)script\.exe$"
        or proc_lc matches regex @"\\powershell(?:\.exe)?$"
        or proc_lc matches regex @"\\cmd\.exe$"
        or proc_lc matches regex @"\\mshta\.exe$"
        or proc_lc matches regex @"\\rundll32\.exe$"
        or proc_lc matches regex @"\\javaw?\.exe$"
    // Evidence of Startup path on the cmdline (avoid broad ".ps1/.bat anywhere" false positives)
    | where cmd_lc has @"\microsoft\windows\start menu\programs\startup\"
        or cmd_lc has @"\programdata\microsoft\windows\start menu\programs\startup\"
    // Typical installer/updater noise (expand with signer/parent checks)
    | where not(cmd_lc contains "azcmagent" or cmd_lc contains "check_updates.ps1")
    | where tolower(parent_process_name) !in ("msiexec.exe","setup.exe","gc_arc_service.exe")
    // Known benign GoogleUpdater uninstall flow
    | where not( cmd_lc has @"\program files (x86)\google\googleupdater\" and cmd_lc has "uninstall.cmd" )
    | extend detection = "startup_exec",
             a_user_name = user_name
    | project time_generated, computer, a_user_name, detection,
              process_id, process_path, command_line, parent_process_name;

// Fire if either signal appears
union s_drop, s_exec
| order by time_generated desc
| extend user_name = coalesce(a_user_name, b_user_name)
| project-away a_user_name, b_user_name
```
