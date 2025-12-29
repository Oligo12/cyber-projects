# Legacy Sentinel Incident Response Lab
**Author:** Nikola Marković                                                                         
**Status:** completed                                                                                                 
**First created on:** 2025-07-05                                                                                                  
**Last updated:** 2025-12-22  
**Repo:** https://github.com/Oligo12/cyber-projects/                                                                   
**Email:** nikola.z.markovic@pm.me                                                                                                 
**LinkedIn:** https://www.linkedin.com/in/nikolazmarkovic/  

---

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

- **[Incident Response Case Study](../incident-response/legacy-sentinel-lab-attack-chain.md)**  
  The incident response timeline for this lab.

---

## Scenario Summary
A phishing attack led to endpoint compromise, persistence via registry modification, reverse shell activity, credential theft, lateral movement to a Domain Controller, privilege escalation, and data exfiltration.  
The incident was detected early via persistence telemetry and investigated using Microsoft Sentinel.

---

## Lab Scope & Progression Note
This lab represents a **foundational Sentinel and incident response implementation** created during my early learning phase.

- Detections prioritize clarity and investigative visibility.
- Alert correlation and automation are intentionally limited to basic analyst notification.
- The focus is on end-to-end SOC workflows rather than production-scale tuning.

For examples of more advanced detection engineering, correlation, and automation, see:
- **[Detection Lab](../detection-lab)**

This lab documents my progression from foundational SOC investigation workflows to more advanced blue-team detection and response work.
