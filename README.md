# Cybersecurity Projects

**Current Focus (Q2 2026):**
- Security-relevant Windows internals deep dive
- Expanding into Linux and basic cloud security concepts
  
**Author:** Nikola Marković  
**Status:** ongoing                                                                                                                              
**Last updated:** 2026-05-04          
**Repo:** https://github.com/Oligo12/cyber-projects/                                                                   
**Email:** nikola.z.markovic@pm.me                                                                                                 
**LinkedIn:** https://www.linkedin.com/in/nikolazmarkovic/  

Current labs and projects:

- [**malware-analysis/**](/malware-analysis) - isolated lab for learning manual Windows malware analysis (e.g., ProcMon, Wireshark). I document behaviors/TTPs per sample.
- [**detection-lab/**](/detection-lab) - small Sentinel-focused lab where I **drop known components from the analyses** to search logs and prototype **KQL detections** (plus basic response). It’s separate because AMA/agents can break after VM snapshot restores; this lab is manually remediated and kept "good enough" for hunting known behaviors.
- [**edr-project/**](/edr-project) - custom Windows EDR prototype detecting in-memory process injection (hollowing, shellcode remote thread, image-based) via a kernel driver, user-mode hook DLL, and rules-based chain scoring. Includes a layered Authenticode trust subsystem (path + LOLBin denylist + embedded/catalog signature verification) for false-positive suppression. Validated against SnakeKeylogger and a Defender-evasive injection sample.
- [**incident-response/**](/incident-response) - incident response case studies linking malware behavior, Sentinel detections, and analyst actions (triage -> containment -> recovery).
- [**legacy-sentinel-ir-lab/**](legacy-sentinel-ir-lab) - Foundational Microsoft Sentinel lab (architecture + detections). The associated IR case study is in [**incident-response/**](/incident-response).
- [**vulnerability-management-openvas-lab/**](/vulnerability-management-openvas-lab) - mini lab demonstrating vulnerability scanning, triage, validation, prioritization, and remediation using OpenVAS (Greenbone). Focused on analyst judgment and communication rather than exploit proof.

Current samples analyzed: SnakeKeylogger, Agent Tesla, Pulsar/Quasar RAT, WannaCry.

License: **The Unlicense** (public domain).
