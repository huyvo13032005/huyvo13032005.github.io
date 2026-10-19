---
title: "Sideload Sentinel: Detecting DLL Sideloading (T1129) with Sysmon and Elastic Security"
excerpt: "Ran an 8-phase APT-style attack chain built around DLL sideloading, engineered detections for MITRE T1129 in Elastic Security, found and documented a false negative, and added a Telegram SOAR playbook."
collection: portfolio
status: done
tools: ["Sysmon", "Elastic Security", "Atomic Red Team", "Sigma", "KQL", "EQL", "MITRE ATT&CK", "Python", "SOAR"]
order: 2
---

**Detection Engineering lab · Windows endpoint · Course project at PTIT**

[GitHub repository](https://github.com/huyvo13032005/sideload-sentinel) · [Detection rules](https://github.com/huyvo13032005/sideload-sentinel/tree/main/detection-rules) · [SOAR scripts](https://github.com/huyvo13032005/sideload-sentinel/tree/main/soar) · [ATT&CK Navigator layer](https://github.com/huyvo13032005/sideload-sentinel/blob/main/mitre-navigator/layer.json)

## Overview

DLL sideloading lets an attacker run code inside a legitimate, trusted process instead of dropping a new executable that antivirus would flag. In MITRE ATT&CK this behavior is **T1129 - Shared Modules** (Execution). It is hard to catch with simple process-name or signature rules, because the process is legitimate and the DLL can even be validly signed.

This project takes that single technique and follows it end to end: simulate it inside a realistic attack chain, work out which telemetry exposes it, write and validate detection logic in Elastic Security, then measure where the detection fails and automate the first response.

<div class="stats">
  <div class="stat"><span class="stat__num">8/8</span><span class="stat__label">Attack phases executed</span></div>
  <div class="stat"><span class="stat__num">~0.5 s</span><span class="stat__label">File create to DLL load (measured)</span></div>
  <div class="stat"><span class="stat__num">&lt; 5 s</span><span class="stat__label">Alert to Telegram (lab)</span></div>
</div>

## How this differs from my insider-threat project

Both projects are detection engineering on Windows with Sysmon and an Elastic SIEM, but they answer different questions.

| | [Insider Threat Detection]({{ site.baseurl }}/portfolio/01-insider-threat-detection/) | Sideload Sentinel (this project) |
|---|---|---|
| Threat model | Malicious insider with a valid account, using only built-in tools | External APT-style intrusion: phishing, DLL sideloading, persistence, C2, exfiltration |
| Approach | **Breadth:** six kill-chain phases, one rule each | **Depth:** one technique (T1129) from telemetry to validation to failure analysis |
| Key telemetry | Sysmon process, network, file, registry and file-delete events | Sysmon image load (EID 7) correlated with file creation (EID 11) |
| Detection | EQL per phase plus a full-chain correlation rule | KQL and Sigma rules plus an EQL file-create to image-load sequence |
| Validation | Positive and negative test cases, full-chain simulation | Real Elastic alert, plus a benign signed-DLL test that exposed a false negative |
| Response | Analyst-driven | SOAR mini playbook (webhook to Telegram) |

## Lab architecture

| Machine | Role |
|---|---|
| Kali Linux | Attacker: HTTP server hosting payloads, reverse-shell listener, exfiltration listener |
| Windows 10 Home | Victim endpoint with Sysmon and Elastic Agent |
| Elastic Security (Elastic Cloud) | SIEM: detection rules and alerts, logs in the `windows.sysmon_operational` data stream |

Atomic Red Team was used for the T1218.011 and T1129 test cases. Telemetry scope was deliberately limited to Sysmon and Windows Event Log (no commercial EDR, no raw network capture).

## Attack chain

The chain has eight phases, mapped to ATT&CK tactics. Note that *Weaponization* is a Lockheed Martin Kill Chain phase, not an ATT&CK tactic, so the mapping is done separately rather than forced.

| # | Phase | ATT&CK | What happened | Detection status |
|---|---|---|---|---|
| 1 | Reconnaissance | T1595 | Active scanning | Out of scope (needs network telemetry) |
| 2 | Weaponization | T1129 | Prepared a malicious `.lnk` and a sideloaded `version.dll` | **Detected** |
| 3 | Delivery | T1566.001 | Phishing email with `Invoice.zip` | Not detected |
| 4 | Exploitation | T1204.002 | User opens the shortcut disguised as a PDF | Not detected |
| 5 | Persistence | T1053.005 | Scheduled task named "WindowsUpdate" running as SYSTEM | Partial |
| 6 | Command and Control | T1071.001 | HTTP beacon and heartbeat | Partial |
| 7 | Discovery | T1033 | `whoami /all` | Not tested |
| 8 | Exfiltration | T1041 | HTTP POST of a staged file | Not tested |

"Partial" means telemetry was captured and the rule logic was mapped, but no working alert was validated. T1595 is out of scope rather than a false negative: its official detection strategy relies on network traffic data that this lab does not collect.

## Detection engineering

### From ATT&CK to telemetry

I started from the official detection strategy for T1129 (DET0018 / AN0052) and mapped its data components to Sysmon events:

| Data component | Sysmon event |
|---|---|
| Process creation | EID 1 |
| Network connection | EID 3 |
| Image load (module load) | EID 7 |
| File creation | EID 11 |
| DNS query | EID 22 |

### Rule 1: suspicious DLL load from a user-writable path (Medium, risk 47)

```kql
event.code: "7" and
(process.name: "powershell.exe" or process.name: "pwsh.exe" or
 process.name: "rundll32.exe" or process.name: "regsvr32.exe") and
(dll.path: *AppData* or dll.path: *Downloads* or
 dll.path: *Users\Public* or dll.path: *Windows\Temp*)
```

A companion rule on Sysmon EID 11 (Low, risk 21) flags the DLL being written to the same kinds of directories. I also wrote the equivalent **Sigma** rule so the logic is portable beyond Elastic.

### Correlation: file creation then image load

The timeline showed a DLL written and then loaded within about half a second (09:18:26.832 to 09:18:27.357). That measurement drove the window of the correlation rule:

```eql
sequence by user.name with maxspan=30s
  [ file where event.code == "11" and file.extension == "dll" and
    file.path : ("*\\AppData\\*", "*\\Downloads\\*",
                 "*\\Users\\Public\\*", "*\\Windows\\Temp\\*") ]
  [ library where event.code == "7" and
    dll.path : ("*\\AppData\\*", "*\\Downloads\\*",
                "*\\Users\\Public\\*", "*\\Windows\\Temp\\*") and
    process.name : ("rundll32.exe", "powershell.exe",
                    "pwsh.exe", "regsvr32.exe") ]
```

The trade-off: requiring both events raises confidence, but a DLL planted long before it is loaded falls outside the 30-second window. This sequence is a design based on measured timing; the alerts I validated in Elastic came from the two single-event rules above.

<figure>
  <img src="{{ site.baseurl }}/images/sideload/filecreate-imageload.png" alt="Elastic Discover showing a file creation event followed by an image load event half a second later">
  <figcaption>File creation (09:18:26.832) followed by the image load (09:18:27.357) in Elastic Discover.</figcaption>
</figure>

<figure>
  <img src="{{ site.baseurl }}/images/sideload/elastic-alert.png" alt="Elastic Security alert Suspicious DLL Load From User-Writable Path with risk score 47">
  <figcaption>Real alert from the lab: powershell.exe loading a DLL from a Temp folder, mapped to Execution / Shared Modules (T1129), risk score 47.</figcaption>
</figure>

## Finding: a false negative

I also tested a benign-looking case with Atomic Red Team (T1218.011): `rundll32.exe` loading the Microsoft-signed `pcwutl.dll` from `System32`. The rule did **not** fire.

<figure>
  <img src="{{ site.baseurl }}/images/sideload/pcwutl-false-negative.png" alt="Sysmon event 7 showing rundll32 loading a validly signed pcwutl.dll from System32">
  <figcaption>Sysmon EID 7: a validly signed system DLL from System32, so a path-only rule misses it.</figcaption>
</figure>

The reason is that the rule only checks the DLL path. An attacker can abuse a legitimate, signed DLL in a trusted location and slip past it. A valid signature does not mean safe, and an odd path alone is not enough.

**Proposed tuning** (based on the Mutable Elements of the official detection strategies):

1. **Signature trust:** exclude known good signers to cut false positives, and treat signed-but-odd-path DLLs as "suspicious" rather than ignoring them.
2. **Parent process:** Office apps, `explorer.exe` opening a `.lnk`, or `rundll32.exe` loading from `System32` each map to a different technique.
3. **Recency:** a DLL created within the last hour before it is loaded deserves higher confidence.

The signer-exclusion variant is written in the repo; the parent-process and recency checks are documented but not yet implemented as rules.

## SOAR mini playbook

To shorten the time from alert to action, I built a small playbook: an Elastic rule action (or a simulator script) sends a webhook to a Flask listener, which extracts the DLL SHA-256 and posts a formatted alert to Telegram with a recommended response (isolate the endpoint, collect forensics).

In the lab the notification arrived in under 5 seconds. It was tested with a single alert and with seven alerts in a row following the kill chain. The seven-alert demo uses simulated payloads, since only T1129 has a real Elastic rule behind it. VirusTotal enrichment is implemented in the code but was not run for lack of an API key, and there is no automatic containment yet. The scripts in the repo are a reference implementation written to match the behavior I observed in the lab.

## Limitations

Stating these plainly is part of the point of a detection project:

- Only **1 of 9 techniques** has a working, validated alert in Elastic.
- **False-positive rate was not measured.** Doing it properly means running a set of legitimate installers for 24 to 48 hours and counting the alerts.
- The correlation rule covers two steps, not the whole attack chain.
- The tuned rule has not been re-tested in the lab.
- Scope is Windows only, although T1129 also applies to Linux and macOS.

## What I learned

- **Measure before you correlate.** The 30-second window came from an observed 0.5-second gap, not a guess.
- **Path-only detection is fragile.** Signer, parent process and file age change the verdict.
- **Know what your telemetry can see.** Marking T1595 as out of scope was more honest than counting it as a miss.
- **Report coverage truthfully.** One validated alert beats a diagram that implies nine.

## Next steps

- Finish detections for the remaining techniques and a correlation rule over the full chain
- Quantify false positives with a legitimate-software baseline
- Implement the parent-process and recency checks
- Production-grade SOAR: real VirusTotal key, auto-containment, case management
