---
layout: archive
title: "CV"
permalink: /cv/
author_profile: true
redirect_from:
  - /resume
---

{% include base_path %}

Education
======
* **Posts and Telecommunications Institute of Technology (PTIT)** - B.S. in Information Security, 2023 - present

Career goal
======
* SOC Analyst (security monitoring engineer)

Certifications and courses
======
* Security Operations Center (SOC), Cisco Learning & Certifications, 2025
  * SOC architecture, IAM, IR, SIEM, SOAR, UEBA, EDR, NIST
* Cybersecurity, IPMac Academy (with hands-on labs)

Skills
======
* **Monitoring and detection (Blue Team):** ELK Stack (SIEM), detection rules, alert tuning, false/true positive triage, correlation, Snort, Suricata
* **Frameworks:** MITRE ATT&CK, Cyber Kill Chain, NIST
* **Network and firewall:** pfSense, IDS/IPS, PCAP analysis
* **Malware analysis:** FLARE-VM, VirusTotal
* **Penetration testing (Red Team):** Metasploit, msfvenom, Nessus, Burp Suite, Atomic Red Team
* **SOC knowledge:** IAM, IR, SIEM, SOAR, UEBA, EDR

Projects
======
* **Insider Threat Detection with Sysmon, Elastic SIEM and MITRE ATT&CK** (course project, PTIT, 2025-2026)
  * Built a hybrid lab (AWS EC2 Windows endpoint with Sysmon and Elastic Agent, local Elastic SIEM) and simulated a six-phase insider kill chain using only LOLBins
  * Wrote EQL detection rules and KQL hunt queries for each phase, mapped to MITRE ATT&CK, plus a kill-chain correlation rule (same host and user, ordered sequence, 2h window)
  * Tuned each rule with exclusions and negative tests to reduce false positives
  * [Write-up]({{ base_path }}/portfolio/01-insider-threat-detection/) · [GitHub](https://github.com/huyvo13032005/Insider-PowerShell-Detection)

Contact
======
* Email: [huyvo9864@gmail.com](mailto:huyvo9864@gmail.com)
* GitHub: [github.com/huyvo13032005](https://github.com/huyvo13032005)
