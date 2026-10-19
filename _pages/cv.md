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
* **Sideload Sentinel: Detecting DLL Sideloading (T1129) with Sysmon and Elastic Security** (course project, PTIT, 2026)
  * Ran an 8-phase APT-style attack chain (phishing, DLL sideloading, persistence, C2, exfiltration) in a Kali / Windows 10 / Elastic Cloud lab
  * Engineered KQL, Sigma and EQL detections for MITRE T1129 from Sysmon image-load and file-create telemetry; validated a real Elastic alert
  * Identified a false negative (signed system DLL from System32) and proposed tuning on signer, parent process and file age
  * Built a Flask webhook to Telegram SOAR playbook (alert to notification in under 5 seconds in the lab)
  * [Write-up]({{ base_path }}/portfolio/02-sideload-sentinel-t1129/) · [GitHub](https://github.com/huyvo13032005/sideload-sentinel)

Contact
======
* Email: [huyvo9864@gmail.com](mailto:huyvo9864@gmail.com)
* GitHub: [github.com/huyvo13032005](https://github.com/huyvo13032005)
