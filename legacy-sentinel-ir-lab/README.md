# Legacy Sentinel Incident Response Lab
**Author:** Nikola Marković                                                                         
**Status:** completed                                                                                                 
**First created on:** 2025-07-05                                                                                                  
**Last updated:** 2025-12-22  
**Repo:** https://github.com/Oligo12/cyber-projects/                                                                   
**Email:** nikola.z.markovic@pm.me                                                                                                 
**LinkedIn:** https://www.linkedin.com/in/nikolazmarkovic/  

---

This project documents a **full incident response case study** built on top of a Microsoft Sentinel detection lab.

The goal of this lab is to demonstrate **how alerts are investigated, scoped, and responded to**, not just how detections are created.

---

## What this lab shows
- Hybrid SOC environment using **Microsoft Sentinel**
- Custom detections for persistence, C2, authentication abuse, and privilege escalation
- End-to-end **incident response workflow**:
  - Triage
  - Investigation
  - Scope assessment
  - Containment
  - Eradication
  - Recovery
  - Lessons learned

---

## Contents
- **[Legacy-Sentinel-Lab](Legacy-Sentinel-Lab.pdf)**  
  Architecture overview, log sources, detection rules, and simulated attack flow.

- **[incident-response-timeline](incident-response-timeline.md)**  
  An incident response timeline documenting analyst actions, decisions, and remediation steps for a simulated critical incident.

---

## Scenario Summary
A phishing attack led to endpoint compromise, persistence via registry modification, reverse shell activity, credential theft, lateral movement to a Domain Controller, privilege escalation, and data exfiltration.  
The incident was detected early via persistence telemetry and investigated using Microsoft Sentinel.

---

## Lab Scope & Progression Note
This lab represents an **early-stage Sentinel and incident response implementation** created during my initial learning phase.

- Alert correlation and advanced automation were intentionally minimal.
- Detections focus on clarity and visibility rather than production-scale tuning.
- Automation is limited to basic analyst notification (Discord alerts).

For examples of **more advanced detection engineering, alert correlation, and automation**, see:
- **[Detection Lab](detection-lab)**

This reflects my progression from foundational SOC workflows to more advanced blue-team detection engineering and incident response work.
