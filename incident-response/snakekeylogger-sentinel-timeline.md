## Incident Response Timeline - SnakeKeylogger (Microsoft Sentinel)

### Incident Summary
- **Incident Type:** Fileless malware loader + keylogger execution
- **Malware Family:** [SnakeKeylogger](../../malware-analysis/SnakeKeylogger/Report.md)
- **Initial Vector:** User-executed PowerShell loader script
- **Primary Detections:**
  - [PowerShell loader behavior (Event ID 4104 - ScriptBlock Logging)](../detection-lab/detections/kql/powerShell_in-memory_loader_behavior.md)
  - [Delayed command execution + respawn watchdog loop (Sysmon)](../../detection-lab/detections/kql/delayed_command_execution_respawn_loop.md)
- **Severity:** High
- **Detection Type:** Behavior-based (no static IOCs)
- **Status:** Detected (lab simulation)

This incident was simulated in a controlled lab environment to validate **custom Microsoft Sentinel analytics rules** and the associated **incident response workflow**.

---

## Environment
- Microsoft Sentinel
- Windows endpoint (domain-joined)
- PowerShell ScriptBlock Logging (**Event ID 4104**)
- Sysmon (**ProcessCreate / ProcessTerminate**)
- Custom KQL analytics rules (behavioral detection)

---

## Timeline of Events

### T0 - Malware Execution
- A user executed a PowerShell-based loader script.
- The script ran non-interactively and initiated a fileless execution chain.
- No immediate file-based malware alerts were generated.

---

### T1 - Loader Behavior Detected
- Sentinel generated a **High severity alert**:
  - **Rule:** *PowerShell loader behavior - obfuscation + in-memory execution*
- Detection triggered due to multiple loader indicators co-occurring in a single ScriptBlock:
  - Base64 decoding logic
  - Dynamic execution (`Invoke-Expression`)
  - In-memory / reflective loading behavior
- Alert evidence included:
  - ScriptBlock content
  - Loader score and indicator breakdown
- Activity classified as **fileless PowerShell loader behavior**.

---

### T2 - Keylogger Payload Execution (inferred from Malware Analysis, EDR not available)
- SnakeKeylogger payload executed in memory.
- Keylogging and credential collection routines initialized.
- Execution required minimal disk interaction.

---

### T3 - Watchdog / Respawn Behavior Detected
- Sentinel generated **Medium severity alert(s)**:
  - **Rule:** *Delayed command execution + respawn watchdog loop*
- Detection characteristics:
  - Repeated process executions
  - Short inter-execution gaps (seconds)
  - Consistent command-line patterns
- Behavior consistent with malware self-monitoring and resiliency mechanisms.

---

### T4 - Alert Correlation
- Multiple alerts occurred within a short timeframe:
  - PowerShell loader alert (high confidence)
  - Respawn / watchdog loop alerts
- Alerts were correlated into incidents for investigation.
- No benign administrative tooling matched the detected behavior.

---

### T5 - Investigation & Validation
- Analyst reviewed:
  - ScriptBlock logging events
  - Process creation timelines
  - Parent/child execution chains
- Confirmed malicious behavior aligned with known SnakeKeylogger tradecraft.
- Incident classified as **True Positive - Malware Execution**.

---

### T6 - Containment (Simulated)
- Endpoint would be isolated from the network.
- Malicious PowerShell execution blocked.
- Affected user credentials flagged for reset.

---

### T7 - Eradication (Simulated)
- Malicious processes terminated.
- PowerShell logging and execution controls verified.

---

### T8 - Recovery
- Endpoint returned to normal operation.
- Heightened monitoring maintained for PowerShell abuse and respawn behavior.

---

## Detection Value Demonstrated
- Successful detection of **fileless malware** without relying on hashes or signatures.
- Behavioral correlation between:
  - PowerShell loader activity
  - Process respawn / watchdog logic
- Demonstrates Sentinel’s ability to detect **early-stage malware execution**.

---

## Analyst Notes
- Incident scope intentionally limited to focus on execution-stage detection.
- Demonstrates realistic SOC workflow:
  - Detection -> Triage -> Investigation -> Response
- Rules are suitable for correlation with persistence, C2, or exfiltration detections in larger attack chains.

