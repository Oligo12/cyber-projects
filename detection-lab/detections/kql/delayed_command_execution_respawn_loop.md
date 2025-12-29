```yaml
title: Delayed command execution + respawn watchdog loop
status: prototype (PoC)
mitre:
  - T1059 (Command and Scripting Interpreter)
  - T1497.003 (Time Based Evasion)
  - T1070 (Indicator Removal on Host)
source:
  - Sysmon EID 1: ProcessCreate
  - Sysmon EID 5: ProcessTerminate
last_updated: 2025-12-29
severity: medium-high
confidence: medium
notes: Lab-oriented behavioral detection; focuses on delayed execution combined with repeated respawn patterns. Intentionally strict to reduce noise.
```

## Summary
Detects **delayed command execution patterns** combined with **short-interval respawn loops**, a common watchdog / evasion technique used by malware to survive crashes, sandbox timeouts, or cleanup attempts.

The rule has two internal triggers:
- **Trigger A** - repeated executions where a *delay primitive* and *action primitive* appear in the same command line within a short window.
- **Trigger B** - a tighter signal that detects **rapid respawn loops** with consistent timing gaps, indicating watchdog behavior.

Trigger B suppresses Trigger A when both fire for the same context to reduce alert noise.

---

## Why this matters
Malware often delays execution (e.g., `timeout`, `ping -n`, `Start-Sleep`) to:
- evade sandbox detonation time limits
- stagger destructive actions
- survive automated remediation

Watchdog-style respawn loops (short execution gaps, repeated starts) are especially suspicious when combined with:
- registry modification
- scheduled task creation
- LOLBins and script hosts
- file deletion or cleanup activity

This rule targets **behavior**, not file hashes or IOCs.

---

## Signal logic

### Trigger A - Delayed command execution (windowed)
- Sysmon **ProcessCreate (EID 1)**
- Command line contains:
  - at least one **delay primitive** (e.g., `timeout`, `ping -n`, `Start-Sleep`)
  - at least one **action primitive** (e.g., `reg add`, `schtasks`, `del`, `bitsadmin`, `certutil`)
- Same normalized command line repeats **4+ times** within a **5-minute window**

Purpose: catch noisy delayed loops without alerting on single executions.

---

### Trigger B - Respawn watchdog loop
- Sysmon **ProcessCreate (EID 1)**
- Same process image and command line respawns with:
  - inter-execution gaps between **1s and 30s**
  - **4+ executions** inside the same 5-minute window
- Optional enrichment with **Sysmon ProcessTerminate (EID 5)** to highlight crash/kill loops

Purpose: detect true watchdog behavior with high confidence.

---

## Suppression logic
When both triggers fire:
- **Trigger B overrides Trigger A**
- Suppression is applied per:
`(window_start_utc, computer, user_name, img_lc, cmd_norm)`

This prevents duplicate alerts while still preserving context for distinct command lines.

---

## Tuning guidance
- Increase `min_starts` if environment is noisy
- Increase `window` if delayed malware uses longer sleep intervals
- Increase `lookback` if your rule runs infrequently.
- Keep strict command-line matching to avoid false positives from legitimate schedulers
- Pair with complementary rules:
  - user-writable -> AppData/Temp drops
  - startup persistence
  - LOLBin misuse
  - scheduled task creation

---

## Known limitations
- Does **not** detect respawn loops with heavily randomized arguments
- Does **not** assert malicious intent alone - designed for correlation
- Lab allowlists recommended before production use

---

## KQL
```kusto
// triggers:
// - trigger_a: delay + action in same command line, repeated within a window (reduces noise)
// - trigger_b: respawn loop in a time window (only alert on loops containing delay+action)
// suppression: trigger_b overrides trigger_a per (window_start, computer, user, img_lc, cmd_norm)

let lookback = 2h;

// trigger_b tuning
let min_gap = 1s;
let max_gap = 30s;
let window = 5m;          // alerting chunk size
let min_starts = 4;       // 4+ starts inside each window

// primitives
let delay_terms = dynamic([
  "timeout", "timeout.exe",
  "ping -n", "ping.exe -n",
  "choice /t", "choice.exe /t", "choice /c", "choice.exe /c",
  "start-sleep"
]);

let action_terms = dynamic([
  "del", "erase",
  "move", "copy",
  "reg add", "reg.exe add",
  "schtasks", "schtasks.exe",
  "rundll32", "rundll32.exe",
  "mshta", "mshta.exe",
  "wscript", "wscript.exe",
  "cscript", "cscript.exe",
  "bitsadmin", "bitsadmin.exe",
  "certutil", "certutil.exe"
]);

let script_hosts = dynamic([
  "powershell.exe","pwsh.exe","powershell_ise.exe",
  "wscript.exe","cscript.exe","mshta.exe","cmd.exe"
]);

// ---- base tables (sysmon only)
let p1 =
    Sysmon_1_ProcessCreate()
    | where time_generated >= ago(lookback)
    | extend
        time_generated_utc      = time_generated,
        computer                = tostring(computer),
        user_name               = tostring(user_name),
        process_path            = tostring(process_path),
        process_name            = tolower(tostring(process_name)),
        command_line            = tostring(command_line),
        parent_process_path     = tostring(parent_process_path),
        parent_process_name     = tolower(tostring(parent_process_name)),
        // optional fields (won't break if missing)
        process_guid            = tostring(column_ifexists("process_guid","")),
        process_id              = tostring(column_ifexists("process_id","")),
        parent_process_guid     = tostring(column_ifexists("parent_process_guid","")),
        parent_process_id       = tostring(column_ifexists("parent_process_id","")),
        current_directory       = tostring(column_ifexists("current_directory","")),
        integrity_level         = tostring(column_ifexists("integrity_level","")),
        hashes                  = tostring(column_ifexists("hashes",""))
    | extend
        cmd_lc = tolower(command_line),
        img_lc = tolower(process_path),
        window_start_utc = bin(time_generated_utc, window)
    | project
        time_generated_utc, window_start_utc, computer, user_name,
        process_path, process_name, command_line,
        parent_process_path, parent_process_name,
        process_guid, process_id, parent_process_guid, parent_process_id,
        current_directory, integrity_level, hashes,
        cmd_lc, img_lc;

let p5 =
    Sysmon_5_ProcessTerminate()
    | where time_generated >= ago(lookback)
    | extend
        time_generated_utc = time_generated,
        computer           = tostring(computer),
        user_name          = tostring(user_name),
        process_path       = tostring(process_path),
        process_name       = tolower(tostring(process_name)),
        process_guid       = tostring(column_ifexists("process_guid","")),
        process_id         = tostring(column_ifexists("process_id",""))
    | extend img_lc = tolower(process_path)
    | project time_generated_utc, computer, user_name, process_path, process_name, img_lc, process_guid, process_id;

// terminate enrichment (used by trigger_b)
// Do not group terminations by cmdline; join must remain 1:1 per (host,user,image,window)
let term_counts =
    p5
    | extend window_start_utc = bin(time_generated_utc, window)
    | summarize
        terminate_count = count(),
        terminate_pids  = make_set(process_id, 32),
        terminate_guids = make_set(process_guid, 32)
      by computer, user_name, img_lc, window_start_utc;

// ------------------------------
// trigger_a: delay + action in same command line, repeated within window
let trigger_a =
    p1
    | where isnotempty(cmd_lc)
    | where cmd_lc has_any (delay_terms) and cmd_lc has_any (action_terms)
    | extend cmd_norm = replace_regex(cmd_lc, @"[""']+", "")
    | extend cmd_norm = replace_regex(cmd_norm, @"\s+", " ")
    | extend cmd_norm = trim(" ", cmd_norm)
    | summarize
        starts_in_window = count(),
        example_command_line = any(command_line),
        example_process_path = any(process_path),
        example_process_name = any(process_name),
        example_parent_path  = any(parent_process_path),
        example_parent_name  = any(parent_process_name),
        example_process_guid = any(process_guid),
        example_process_id   = any(process_id),
        example_parent_process_guid = any(parent_process_guid),
        example_parent_process_id   = any(parent_process_id),
        example_current_directory   = any(current_directory),
        example_integrity_level     = any(integrity_level),
        example_hashes              = any(hashes)
      by window_start_utc, computer, user_name, img_lc, cmd_norm
    | where starts_in_window >= 4
    | extend
        trigger_type = "trigger_a_delay_plus_action_windowed",
        reason = strcat(
            "delay+action within window: starts=", tostring(starts_in_window),
            "; window=", tostring(window),
            iff(tolower(example_parent_name) in (script_hosts), " | parent_is_script_host", "")
        )
    | project
        time_generated_utc = window_start_utc,
        window_start_utc,
        computer, user_name,
        img_lc,
        cmd_norm,
        trigger_type, reason,
        process_path = example_process_path,
        process_name = tostring(split(tolower(example_process_path), "\\")[-1]),
        command_line = example_command_line,
        parent_process_path = example_parent_path,
        parent_process_name = example_parent_name,
        process_guid = example_process_guid,
        process_id = example_process_id,
        parent_process_guid = example_parent_process_guid,
        parent_process_id = example_parent_process_id,
        current_directory = example_current_directory,
        integrity_level = example_integrity_level,
        hashes = example_hashes,
        starts_in_window;

// ------------------------------
// trigger_b: windowed respawn loop (only alert on loops that contain delay+action)
let trigger_b =
    p1
    | where isnotempty(img_lc) and isnotempty(cmd_lc)
    | where cmd_lc has_any (action_terms) and cmd_lc has_any (delay_terms)
    | extend cmd_norm = replace_regex(cmd_lc, @"[""']+", "")
    | extend cmd_norm = replace_regex(cmd_norm, @"\s+", " ")
    | extend cmd_norm = trim(" ", cmd_norm)
    | sort by computer asc, user_name asc, img_lc asc, cmd_lc asc, window_start_utc asc, time_generated_utc asc
    | serialize
    | extend prev_t = prev(time_generated_utc)
    | extend same_key =
        (prev(computer) == computer
         and prev(user_name) == user_name
         and prev(img_lc) == img_lc
         and prev(cmd_lc) == cmd_lc
         and prev(window_start_utc) == window_start_utc)
    // FIX: simpler + safer gap calc
    | extend gap = time_generated_utc - prev_t
    | where same_key and gap between (min_gap .. max_gap)
    | summarize
        links_in_window              = count(),
        first_seen_utc               = min(time_generated_utc),
        last_seen_utc                = max(time_generated_utc),
        min_gap_seen                 = min(gap),
        max_gap_seen                 = max(gap),
        example_command_line         = any(command_line),
        example_process_path         = any(process_path),
        example_parent_path          = any(parent_process_path),
        example_parent_name          = any(parent_process_name),
        example_process_guid         = any(process_guid),
        example_process_id           = any(process_id),
        example_parent_process_guid  = any(parent_process_guid),
        example_parent_process_id    = any(parent_process_id),
        example_current_directory    = any(current_directory),
        example_integrity_level      = any(integrity_level),
        example_hashes               = any(hashes)
      by window_start_utc, computer, user_name, img_lc, cmd_norm
    | extend starts_in_window = links_in_window + 1
    | where starts_in_window >= min_starts
    | join kind=leftouter term_counts on computer, user_name, img_lc, window_start_utc
    | extend
        trigger_type = "trigger_b_respawn_loop_windowed",
        reason = strcat(
            "respawn loop within window: starts=", tostring(starts_in_window),
            "; window=", tostring(window),
            "; gap_seen=", tostring(min_gap_seen), "-", tostring(max_gap_seen),
            iff(isnull(terminate_count), "", strcat(" | terminations=", tostring(terminate_count)))
        )
    | project
        time_generated_utc = window_start_utc,
        window_start_utc,
        computer, user_name,
        img_lc,
        cmd_norm,
        trigger_type, reason,
        process_path = example_process_path,
        process_name = tostring(split(tolower(example_process_path), "\\")[-1]),
        command_line = example_command_line,
        parent_process_path = example_parent_path,
        parent_process_name = example_parent_name,
        process_guid = example_process_guid,
        process_id = example_process_id,
        parent_process_guid = example_parent_process_guid,
        parent_process_id = example_parent_process_id,
        current_directory = example_current_directory,
        integrity_level = example_integrity_level,
        hashes = example_hashes,
        starts_in_window,
        min_gap_seen,
        max_gap_seen,
        terminate_count,
        terminate_pids,
        terminate_guids;

// final output
union trigger_a, trigger_b
| extend trigger_rank = case(trigger_type startswith "trigger_b", 2, 1)
// Suppression: keep highest-signal trigger per (window, host, user, image, cmd_norm)
| summarize arg_max(trigger_rank, *) by window_start_utc, computer, user_name, img_lc, cmd_norm
| project-away trigger_rank
| extend
    severity   = case(trigger_type startswith "trigger_b", "high", "medium"),
    confidence = case(trigger_type startswith "trigger_b", 85, 65)
| order by time_generated_utc desc
```
