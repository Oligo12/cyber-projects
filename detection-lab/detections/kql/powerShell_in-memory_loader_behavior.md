```yaml
title: PowerShell loader behavior (4104) - obfuscation + in-memory execution (score-based)
status: prototype (prod-leaning)
mitre:
  - T1059.001 (PowerShell)
  - T1027 (Obfuscated/Compressed Files and Information)
  - T1620 (Reflective Code Loading) # behavior proxy (no EDR visibility)
source:
  - Windows 4104: PowerShell ScriptBlock
last_updated: 2025-12-29
severity: high
confidence: medium-high
notes: Generalized "PS loader" detector. Fires when multiple loader-like indicators co-occur in the same ScriptBlock. Tune allowlists for your environment.
```
---

## Summary

Detects suspicious PowerShell script blocks that look like malware loaders: obfuscation + dynamic execution / reflection, often used by fileless stagers (including SnakeKeylogger’s chain), but generalized with production environments in mind.

## Why this matters
PowerShell is one of the most abused execution environments on Windows because it enables **fileless execution**, **in-memory payload loading**, and **living-off-the-land** tradecraft without dropping obvious artifacts to disk.

Modern malware loaders frequently rely on combinations of:
- **obfuscation** (Base64, XOR, byte arrays)
- **dynamic execution** (`Invoke-Expression`)
- **reflection / in-memory loading** (`Assembly::Load`, `Add-Type`)
- **network retrieval** (staged payloads via HTTP)

Individually, these techniques can be legitimate.  
When **multiple loader-like behaviors co-occur in the same script block**, however, it strongly indicates a **malicious staging or loader pattern**, especially in fileless attacks and post-exploitation frameworks.

This rule focuses on **behavioral intent**, not specific malware families, making it resilient to minor obfuscation changes and useful across many campaigns.

---

## Signal logic
This is a **score-based behavioral detector** built on **PowerShell ScriptBlock Logging (Event ID 4104)**.

Each script block is evaluated for the presence of common loader characteristics:

- **Dynamic execution**
  - `Invoke-Expression` / `iex`
- **Encoded or obfuscated payloads**
  - `FromBase64String`
  - long Base64-like strings
- **In-memory / reflective loading**
  - `Assembly::Load`
  - `System.Reflection.Assembly`
  - `Add-Type`
- **Staged payload retrieval**
  - `Invoke-WebRequest`
  - `DownloadString`
  - `WebClient` / `HttpClient`
- **Byte-level decoding / XOR**
  - `-bxor`
  - explicit `[byte[]]` handling
  - UTF8 byte conversions

Each indicator contributes **1 point** to a cumulative score.

The alert fires when:
- **Score ≥ `minScore`** (default: 2)

Severity tiers are assigned based on total score:
- **4–5 indicators** -> High confidence loader
- **3 indicators** -> Medium–high confidence
- **2 indicators** -> Medium confidence (review recommended)

Basic allowlisting is applied to suppress known administrative tooling, but the rule is intentionally conservative and designed for **correlation**, not standalone conviction.

---

## KQL
```kusto
// TUNING NOTE / LIMITATION:
// PowerShell EID 4104 may split a single script block across multiple events
// (due to ScriptBlockText size limits). This rule currently scores indicators
// per individual 4104 event, meaning indicators spread across multiple chunks
// of the same ScriptBlockId may not reach minScore and can cause false negatives.
//
// FUTURE TUNING:
// Quick fix: roll up indicators by ScriptBlockId (max() per indicator) to handle indicators split across chunks.
// Better but heavier fix: reconstruct full ScriptBlockText (ScriptBlockId + MessageNumber ordering) before scoring to also
// catch tokens split across chunk boundaries (e.g., "IEX" split as "IE" + "X").

let minScore = 2; // tuning: increase to 3+ in noisy environments
let minBase64Len = 200;

let benign_cmd_patterns = dynamic([
  // Lab allowlist for common admin / management tooling (expand per environment)
  "\\\\program files\\\\",                   // broad
  "chocolatey",
  "winget",
  "azureconnectedmachineagent",
  "azuremonitoragent",
  "microsoft intune",
  "sccm",
  "ansible",
  "saltstack"
]);

let is_benign = (txt:string) {
  tolower(tostring(txt)) matches regex strcat(@"(", strcat_array(benign_cmd_patterns, "|"), @")")
};

win_4104_powershell_scriptblock
| where isnotempty(script_block_text)
| extend sb = tolower(tostring(script_block_text))
| where not(is_benign(sb))
| extend
    // Loader-related behavior indicators (individually weak, strong in combination)
    ind_iex        = iif(sb has "invoke-expression" or sb has " iex " or sb startswith "iex ", 1, 0),
    ind_b64        = iif(sb has "frombase64string" or sb matches regex strcat(@"[a-z0-9\+/]{", tostring(minBase64Len), ",}={0,2}"), 1, 0),
    ind_reflect    = iif(sb has "assembly::load" or sb has "system.reflection.assembly" or sb has "reflection.assembly" or sb has "add-type", 1, 0),
    ind_web        = iif(sb has "invoke-webrequest" or sb has "downloadstring" or sb has "webclient" or sb has "httpclient", 1, 0),
    ind_xor_bytes  = iif(sb has "-bxor" or sb has "[byte[]]" or (sb has "utf8.getstring" and sb has "getbytes"), 1, 0)
| extend score = ind_iex + ind_b64 + ind_reflect + ind_web + ind_xor_bytes
| where score >= minScore
| extend det_rule = case(
    score >= 4, "PS_Loader_HighConfidence",
    score == 3, "PS_Loader_MediumHigh",
               "PS_Loader_Medium"
  )
| extend evidence = strcat(
    "score=", tostring(score),
    " | IEX=", tostring(ind_iex),
    " B64=", tostring(ind_b64),
    " Reflect=", tostring(ind_reflect),
    " Web=", tostring(ind_web),
    " XOR/Bytes=", tostring(ind_xor_bytes)
  )
| project time_generated, computer, det_rule,
          user_name = tostring(column_ifexists("user_name","")),
          evidence,
          script_block_text
| sort by time_generated desc
```
