```yaml
title: AppData-Local first-seen EXE (new folder)
status: prototype (PoC)
mitre:
  - T1204 (User Execution)
source:
  - Sysmon EID 11: FileCreate
  - Sysmon EID 1: ProcessCreate
last_updated: 2025-12-28
severity: medium
confidence: medium
notes: Flags first EXE created under AppData\Local\<folder> (10m window) and enriches with nearest ProcessCreate by PID; lab allowlists only.
```
---

## Summary
Detects first-seen EXE creation under AppData\Local\\\<folder> (user-writable path). Good early signal for payload drops/unpack.

## Why this matters
Attackers commonly drop or unpack binaries in AppData\Local to avoid UAC and blend with user data. Catching the first EXE in a new folder reduces noise and highlights foothold/setup activity.

## Signal logic
- **base** - EXE created under \appdata\local\...; the folder’s first write seen within 10m; excludes common benign folders/creators (lab allowlist).
- **enrichment** - Left-join nearest ProcessCreate (EID 1) for the same PID within 10m to add command_line and parent info.
  
---

## KQL
```kusto
// FileCreate (Sysmon EID 11) - normalize fields
let fc = Sysmon_11_FileCreate()
| where isnotempty(target_filename)
| extend target_filename_s = tostring(target_filename)
| extend path = tolower(target_filename_s),
         pid_s = tostring(process_id);

// Candidate EXEs created under AppData\Local\<folder>
let exes = fc
| extend ext = iff(
      isempty(tostring(file_ext)),
      tostring(extract(@"\.([a-z0-9]{1,8})$", 1, path)),
      tolower(tostring(file_ext))
  )
| where path has @"\appdata\local\" and ext == "exe"
| extend parent_folder = extract(@"(.*\\appdata\\local\\[^\\]+)\\", 1, path)
| where isnotempty(parent_folder);

// First observed write in each parent folder (baseline)
let first_seen_parent = fc
| extend parent_folder = extract(@"(.*\\appdata\\local\\[^\\]+)\\", 1, path)
| where isnotempty(parent_folder)
| summarize first_seen = min(time_generated) by parent_folder;

// Allowlists (lab-only, replace with richer checks in production)
let allowed_parent_folders = dynamic([
  "\\appdata\\local\\microsoft\\",
  "\\appdata\\local\\packages\\",
  "\\appdata\\local\\windowsapps\\",
  "\\appdata\\local\\package cache\\",
  "\\appdata\\local\\packagecache\\",
  "\\appdata\\local\\discord"
]);
let allowed_creators = dynamic([
  "sysmon.exe","onedrive.exe","onedrivesetup.exe","msiexec.exe","setup.exe","installer.exe"
]);

// Base detection: suspicious EXEs in new parent folders within 10m
let base = exes
| join kind=inner (first_seen_parent) on parent_folder
| where time_generated - first_seen <= 10m
| where not(tolower(parent_folder) has_any (allowed_parent_folders))
| where tolower(process_name) !in (allowed_creators)
| project time_generated, computer, user_name, parent_folder,
          target_filename_s, process_name, process_path, pid_s;

// ProcessCreate (Sysmon EID 1) for enrichment
let pc = Sysmon_1_ProcessCreate()
| extend pid_s = tostring(process_id)
| project pc_time = time_generated, computer, pid_s,
          command_line, parent_process_name, parent_process_path;

// Enrich Rule hits with nearest ProcessCreate for same PID (within 10m)
base
| join kind=leftouter (pc) on computer, pid_s
| extend time_diff_s = abs(datetime_diff('second', time_generated, pc_time))
| where isnull(time_diff_s) or time_diff_s <= 600
| summarize arg_min(time_diff_s, *) by time_generated, computer, pid_s, target_filename_s
| project time_generated, computer, user_name,
          parent_folder, target_filename = target_filename_s,
          process_name, process_path, process_id = pid_s,
          command_line, parent_process_name, parent_process_path, time_diff_s
| order by time_generated desc
```
