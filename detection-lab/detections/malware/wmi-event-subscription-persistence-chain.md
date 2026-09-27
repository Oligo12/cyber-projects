```yaml
title: WMI Event Subscription persistence chain - executable consumers + binding correlation
status: prototype (PoC)
mitre:
  - T1546.003 (Event Triggered Execution: WMI Event Subscription)
  - T1059 (Command and Scripting Interpreter) # when consumer is script/command based
  - T1218 (Signed Binary Proxy Execution)     # when consumer/command uses LOLBins
source:
  - Sysmon EID 19: WmiEventFilter
  - Sysmon EID 20: WmiEventConsumer
  - Sysmon EID 21: WmiEventConsumerToFilter
last_updated: 2026-02-01
severity: high
confidence: medium-high
notes: Detects creation of a WMI persistence subscription by correlating Filter + Consumer + Binding.
Raises confidence when consumer destination/template includes common execution hosts (LOLBins).
Designed for correlation and triage; tune allowlists for your environment.
```
---

## Summary
Detects **WMI Event Subscription persistence** by correlating the creation of:
- **WMI Event Filter** (Sysmon 19)
- **WMI Event Consumer** (Sysmon 20) with *executable/script-like consumer types*
- **WMI Binding** (Sysmon 21) connecting a filter to a consumer

Provides two triggers:
- **Trigger A:** Binding + “executable/script-y” consumer
- **Trigger B:** Full chain (Filter + Consumer + Binding) within a short time window (high confidence)

Trigger B suppresses Trigger A for the same host + consumer/filter to avoid duplicates.

---

## Why this matters
WMI Event Subscriptions are a classic **stealthy persistence** mechanism on Windows because they can:
- Survive reboots and user logons (depending on subscription scope)
- Run scripts/commands without obvious Startup/RunKey artifacts
- Blend into legitimate enterprise management tooling

If an attacker creates an **ActiveScript** or **CommandLine** consumer and binds it to a filter, that is often an **autonomous execution chain** that will fire whenever the filter condition matches.

---

## Signal logic

### Data model
This rule assumes normalized helper functions exist in your workspace:
- `Sysmon_19_WmiEventFilter()`
- `Sysmon_20_WmiEventConsumer()`
- `Sysmon_21_WmiEventBinding()`

### Consumer focus (“executable/script-y”)
Targets consumer types commonly used to execute code:
- `CommandLineEventConsumer`
- `ActiveScriptEventConsumer`

### Trigger A - Binding + executable consumer
- Join **Binding (21)** to **Consumer (20)** on `(computer, consumer_name)`
- Require timestamps within `window` (default **10m**)
- Raise confidence/severity if consumer references a known execution host (LOLBins) in:
  - `destination`
  - `command_line_template`

### Trigger B - Full chain (Filter + Consumer + Binding)
- Join Trigger A results to **Filter (19)** on `(computer, filter_name)`
- Require timestamps within `window`
- Mark **high confidence / high severity**

### Suppression
If Trigger B exists for `(computer, consumer_name, filter_name)`, suppress Trigger A for the same tuple.

---

## Tuning guidance
- **`lookback`**: increase if your analytics rule runs infrequently.
- **`window`**: increase if you expect slower, staged creation (e.g., scripts that create filter/consumer/binding minutes apart).
- **`suspicious_consumer_types`**: expand if you want broader coverage (at the cost of noise).
- **Allowlisting:**
  - Add known-good destinations/templates (SCCM, monitoring agents, OEM tooling, etc.).
  - Consider allowlisting by signer / known management tooling process context (best), not just path strings.
- **LOLBins list**: used only for confidence, not alerting. 

---

## Known limitations

- Requires Sysmon coverage for EIDs **19/20/21** (and correct collection into Sentinel).
- Some environments legitimately use WMI subscriptions (e.g. SCCM, monitoring, OEM tooling), so tuning and allowlisting are expected.
- Consumer types outside the targeted executable/script consumers (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`) are intentionally excluded to reduce noise.
- The rule is optimized for **short-window correlation**; attackers who create or modify WMI objects over long periods may not fully correlate within the time window.
- Deduplication using `arg_max()` retains the **latest observed state** of WMI objects within the lookback period; evidence fields may therefore reflect a later benign modification rather than the original malicious configuration.
- This detection should be complemented by a **lower-priority alert** for standalone WMI Consumer or Binding creation/modification with allowlisting to provide coverage for slow or staged persistence setups.

---

## KQL
```kusto
let lookback = 24h;
let window   = 10m;

// "Executable/script-y" consumers
let suspicious_consumer_types = dynamic([
  "command line",   // CommandLineEventConsumer
  "active script"   // ActiveScriptEventConsumer
]);

// Optional allowlist
// let allow_destination_patterns = dynamic([
//   "\\program files\\microsoft configuration manager\\",
//   "\\program files\\microsoft monitoring agent\\",
//   "\\program files\\dell\\",
//   "\\program files\\hp\\"
// ]);
// let is_allowed = (txt:string) { tolower(tostring(txt)) has_any (allow_destination_patterns) };

// LOLBin matcher (enrichment only)
let is_lolbin = (txt:string) {
  let t = tolower(tostring(txt));
  t matches regex @"(^|\\)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msbuild|installutil|wmic)\.exe(\s|$)"
  or t endswith @"\powershell.exe"
  or t endswith @"\pwsh.exe"
  or t endswith @"\cmd.exe"
  or t endswith @"\wscript.exe"
  or t endswith @"\cscript.exe"
  or t endswith @"\mshta.exe"
  or t endswith @"\rundll32.exe"
  or t endswith @"\regsvr32.exe"
  or t endswith @"\msbuild.exe"
  or t endswith @"\installutil.exe"
  or t endswith @"\wmic.exe"
};

// -------------------------
// EID 19: Filter (dedup)
// -------------------------
let f =
    Sysmon_19_WmiEventFilter()
    | where time_generated >= ago(lookback)
    | where tolower(operation) in~ ("created", "modified")
    | extend filter_name = wmi_filter_name
    // keep only the most recent record per host+filter_name (prevents join fan-out)
    | summarize arg_max(time_generated, *) by computer, filter_name
    | project
        f_time = time_generated,
        computer,
        f_user_name = user_name,
        wmi_filter_name = filter_name,
        filter_name,
        query_one_line,
        wmi_filter_query;

// -------------------------
// EID 20: Consumer (dedup)
// -------------------------
let c =
    Sysmon_20_WmiEventConsumer()
    | where time_generated >= ago(lookback)
    | where tolower(operation) in~ ("created", "modified")
    | extend
        consumer_type_lc = tolower(consumer_type),
        destination_lc   = tolower(destination),
        command_line_template = tostring(column_ifexists("command_line_template",
                                column_ifexists("CommandLineTemplate", "")))
    | where consumer_type_lc has_any (suspicious_consumer_types)
    | extend consumer_name = wmi_consumer_name
    | extend has_suspicious_bin = iif(is_lolbin(destination_lc) or is_lolbin(command_line_template), true, false)
    // optional allowlist 
    // | where not(is_allowed(destination_lc)) and not(is_allowed(command_line_template))
    // keep only the most recent record per host+consumer_name (prevents join fan-out)
    | summarize arg_max(time_generated, *) by computer, consumer_name
    | project
        c_time = time_generated,
        computer,
        c_user_name = user_name,
        wmi_consumer_name = consumer_name,
        consumer_name,
        consumer_type,
        destination,
        destination_lc,
        command_line_template,
        has_suspicious_bin;

// -------------------------
// EID 21: Binding (dedup)
// -------------------------
let b =
    Sysmon_21_WmiEventBinding()
    | where time_generated >= ago(lookback)
    | where tolower(operation) in~ ("created", "modified")
    // keep only the most recent record per host+consumer_name+filter_name (prevents join fan-out)
    | summarize arg_max(time_generated, *) by computer, consumer_name, filter_name
    | project
        b_time = time_generated,
        computer,
        b_user_name = user_name,
        consumer_class,
        consumer_name,
        filter_name,
        consumer_raw,
        filter_raw;

// ---------- Trigger A: binding + consumer (executable consumer) ----------
let trigger_a =
    b
    | join kind=inner (c) on computer, consumer_name
    | where c_time between (b_time - window .. b_time + window)
    | extend
        trigger_type = "trigger_a_binding_plus_consumer",
        confidence   = iif(has_suspicious_bin, "high", "medium-high"),
        severity     = iif(has_suspicious_bin, "high", "medium"),
        user_name    = coalesce(b_user_name, c_user_name),
        time_generated = max_of(b_time, c_time),
        evidence = strcat(
            "binding+consumer | consumer=", consumer_name,
            " type=", consumer_type,
            " dest=", substring(tostring(destination), 0, 180),
            iff(isempty(command_line_template), "", strcat(" template=", substring(command_line_template, 0, 120)))
        )
    | project
        time_generated,
        computer,
        user_name,
        trigger_type,
        severity,
        confidence,
        evidence,
        consumer_class,
        consumer_name,
        consumer_type,
        destination,
        command_line_template,
        filter_name;

// ---------- Trigger B: full chain (filter + consumer + binding) ----------
let trigger_b =
    trigger_a
    | join kind=inner (f) on computer, filter_name
    | where f_time between (time_generated - window .. time_generated + window)
    | extend
        trigger_type = "trigger_b_full_chain",
        confidence   = "high",
        severity     = "high",
        evidence = strcat(evidence, " | filter=", filter_name, " | wql=", substring(query_one_line, 0, 180))
    | project
        time_generated,
        computer,
        user_name,
        trigger_type,
        severity,
        confidence,
        evidence,
        consumer_class,
        consumer_name,
        consumer_type,
        destination,
        command_line_template,
        wmi_filter_name = filter_name,
        query_one_line;

// Suppression: if trigger_b exists for same host + consumer/filter, suppress trigger_a
let b_keys =
    trigger_b
    | project computer, consumer_name, wmi_filter_name;

trigger_b
| union (
    trigger_a
    | join kind=leftanti (b_keys) on computer, consumer_name, $left.filter_name == $right.wmi_filter_name
)
| order by time_generated desc
```

