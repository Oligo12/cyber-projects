```yaml
title: User-writable parent -> AppData/Temp drop (3m window)
status: prototype (PoC)
mitre:
  - T1204 (User Execution)
source:
  - Sysmon EID 1: ProcessCreate
  - Sysmon EID 11: FileCreate
last_updated: 2025-12-28
severity: medium
confidence: medium
notes: Correlates a process launched by a user-writable parent with near-term drops into AppData/Temp/Desktop; lab allowlists only.
```

---

## Summary
Detects when a process whose parent image resides in a user-writable path (Users/AppData/ProgramData/Temp) starts and then writes files into AppData/Temp/Desktop shortly after. This is a common unpack/drop pattern right after initial execution.

## Why this matters
Malware frequently launches from user-writable directories to avoid UAC and quickly stages payloads nearby. Correlating the process start -> file drop relationship within a short window cuts noise and spotlights foothold/setup behavior early.

## Signal logic
- **parents** - child processes whose parent image path is user-writable (and not \Windows\*), with lab allowlists to trim Discord/OneDrive/Defender noise.
- **drops** - Sysmon EID 11 writes into AppData\Local, AppData\Roaming, Temp, or Desktop.
- **join & summarize** - correlate by PID and time (default 3m window), then summarize examples (targets/exts) for triage.

---

## KQL
```kusto
let window = 3m;

// Candidate set: child processes whose parent image path is user-writable (not \Windows\*)
let parents =
    Sysmon_1_ProcessCreate()
    | extend parent_path = tolower(tostring(parent_process_path)),
             proc_path_lc = tolower(tostring(process_path)),
             comp_s = tostring(computer),
             user_s = tostring(column_ifexists("user_name",""))
    | where isnotempty(parent_path)
    | where parent_path has_any(@"\users\", @"\appdata\", @"\programdata\", @"\local\temp\")
    | where parent_path !has @"\windows\"
    // Tuning: exclude WerFault (crash handler) noise from parent context
    | where tolower(tostring(parent_process_name)) != "werfault.exe"
    // Lab-only allowlist to cut noise (replace with EDR/AV + TI correlation in prod)
    | where parent_path !in (
        @"c:\users\shawnspencer\appdata\local\microsoft\onedrive\update\onedrivesetup.exe",
        @"c:\users\shawnspencer\appdata\local\discord\update.exe",
        @"c:\programdata\microsoft\windows defender\platform\4.18.25080.5-0\msmpeng.exe",
        @"c:\users\shawnspencer\appdata\local\microsoft\onedrive\onedrivestandaloneupdater.exe"
      )
    | project p_time = time_generated,
              computer = comp_s,
              process_id,
              process_path = proc_path_lc,
              command_line,
              parent_process_id,
              parent_process_path = parent_path,
              parent_process_name,
              parent_command_line,
              user_name = user_s;

// Drops: file creates into Temp/AppData/Desktop within `window` of the child's start time (p_time)
let drops =
    Sysmon_11_FileCreate()
    | extend tgt = tolower(tostring(target_filename)),
             comp_s = tostring(computer)
    | where isnotempty(tgt)
    | where tgt has_any(@"\appdata\local\", @"\appdata\roaming\", @"\local\temp\", @"\temp\", @"\desktop\")
    | where tgt !has @"\appdata\local\google\chrome\user data\default\cache\"
      and tgt !has @"\appdata\local\microsoft\edge\user data\default\cache\"
      and not(tgt matches regex @"\\~\$.+\.(docx|xlsx|pptx)$")
    // Fill extension if Sysmon didn't populate file_ext (derive from path)
    | extend file_ext = tolower(iff(isempty(tostring(file_ext)),
                                tostring(extract(@"\.([a-z0-9]{1,8})$", 1, tgt)),
                                tostring(file_ext)))
    | project file_time = time_generated,
              computer = comp_s,
              process_id,
              target_filename = tgt,
              file_ext;

// Join EID 1 (process start) <-> EID 11 (file create) for the same child PID
parents
| join kind=inner (drops) on computer, process_id
| where file_time between (p_time .. p_time + window)
| summarize
    first_seen      = min(file_time),
    last_seen       = max(file_time),
    drop_events     = count(),
    sample_targets  = make_set(target_filename, 15),
    sample_exts     = make_set(file_ext, 10),
    arg_max(file_time, process_id, parent_process_id, command_line, parent_command_line, process_path, parent_process_path)
  by bin(file_time, 10m),
     computer,
     tostring(process_path),
     tostring(parent_process_path),
     tostring(parent_process_name),
     tostring(user_name)
| project time_generated = first_seen,
         last_seen,
         drop_events,
         computer,
         user_name            = tostring(user_name),
         parent_process_name  = tostring(parent_process_name),
         parent_process_path  = tostring(parent_process_path),
         parent_process_id,
         process_path         = tostring(process_path),
         process_id,
         command_line,
         parent_command_line,
         sample_exts,
         sample_targets
| order by last_seen desc
```
