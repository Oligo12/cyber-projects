# Cybersecurity Projects
**Author:** Nikola Marković  
**Status:** ongoing                                                                                                                              
**Last updated:** 2025-12-29          
**Repo:** https://github.com/Oligo12/cyber-projects/                                                                   
**Email:** nikola.z.markovic@pm.me                                                                                                 
**LinkedIn:** https://www.linkedin.com/in/nikolazmarkovic/  

Current labs and projects:

- [**malware-analysis/**](/malware-analysis) - isolated lab for learning manual Windows malware analysis (e.g., ProcMon, Wireshark). I document behaviors/TTPs per sample.
- [**detection-lab/**](/detection-lab) - small Sentinel-focused lab where I **drop known components from the analyses** to search logs and prototype **KQL detections** (plus basic response). It’s separate because AMA/agents can break after VM snapshot restores; this lab is manually remediated and kept "good enough" for hunting known behaviors.
- [**vulnerability-management-openvas-lab/**](/vulnerability-management-openvas-lab) - mini lab demonstrating vulnerability scanning, triage, validation, prioritization, and remediation using OpenVAS (Greenbone). Focused on analyst judgment and communication rather than exploit proof.
- [**incident-response/**](/incident-response) - incident response case studies linking malware behavior, Sentinel detections, and analyst actions (triage -> containment -> recovery).
- [**legacy-sentinel-ir-lab/**](legacy-sentinel-ir-lab) - Foundational Microsoft Sentinel lab (architecture). The associated IR case study is in [**incident-response/**](/incident-response).

Current samples analyzed: SnakeKeylogger, Agent Tesla, QuasarRAT, WannaCry.

License: **The Unlicense** (public domain).
