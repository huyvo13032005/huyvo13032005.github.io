---
title: "Insider Threat Detection with Sysmon, Elastic SIEM and MITRE ATT&CK"
excerpt: "Simulated a six-phase insider attack that uses only built-in Windows tools (PowerShell, reg, wevtutil), then built EQL detection rules for each phase and a kill-chain correlation rule in Elastic SIEM."
collection: portfolio
status: done
tools: ["Sysmon", "Elastic SIEM", "Elastic Agent", "EQL", "KQL", "MITRE ATT&CK", "PowerShell", "AWS EC2"]
order: 1
---

**Course project at PTIT (2025-2026) · Blue Team / Detection Engineering**

[GitHub repository](https://github.com/huyvo13032005/Insider-PowerShell-Detection) · [Full report (PDF, Vietnamese)](https://github.com/huyvo13032005/Insider-PowerShell-Detection/blob/main/bao-cao-phat-hien-insider-threat.pdf) · [Slides (PDF)](https://github.com/huyvo13032005/Insider-PowerShell-Detection/blob/main/slide-insider-threat.pdf)

## Overview

A malicious insider has a valid account and uses legitimate tools, so there is no malware or exploit to flag. This project asks: can a SOC still catch the activity by looking at behavior and sequence instead of signatures?

I built a lab, simulated a complete insider kill chain, and wrote detection rules for every phase in Elastic SIEM. Each rule is mapped to MITRE ATT&CK, and a final correlation rule ties all six phases together so that one critical alert replaces six separate medium-confidence ones.

## Threat scenario

| Attribute | Value |
|---|---|
| Actor | Malicious insider (`ituser`), valid non-admin account |
| Technique | Living-off-the-Land: PowerShell and built-in Windows utilities only |
| Target | Sensitive project files on a Windows endpoint |
| Goal | Exfiltrate the data, then destroy evidence |
| Telemetry | Sysmon, Elastic Agent, Elastic SIEM |

## Lab architecture

A hybrid lab: the insider endpoint runs in the cloud and the SIEM runs locally.

- **Insider endpoint:** AWS EC2 Windows instance (t3.large) with Sysmon and Elastic Agent
- **SIEM:** Elasticsearch, Kibana and Fleet on a local Windows 10 machine
- **Connectivity:** Elastic Agent sends logs over HTTPS (ports 8220 and 9200, opened in the EC2 security group and Windows Firewall)

```
Windows endpoint (ituser)
  PowerShell activity
        |  Sysmon: EID 1 process, 3 network, 11 file create,
        |          13 registry set, 23 file delete
        v
  Windows Event Log (Sysmon/Operational, PowerShell/Operational)
        |
        v
  Elastic Agent (Fleet) -> ECS field mapping -> HTTPS
        |
        v
  Elasticsearch data stream: logs-windows.sysmon_operational-*
        |
        v
  Elastic SIEM detection engine (EQL rules, every 5 minutes)
        |
        v
  Alerts -> SOC analyst investigation
```

## Kill chain and detection coverage

Each phase has an EQL detection rule and a KQL hunting query.

| # | Phase | Behavior simulated | MITRE ATT&CK | Sysmon EID | Risk |
|---|---|---|---|---|---|
| 1 | Execution | PowerShell with `-ExecutionPolicy Bypass`, hidden window, encoded commands | T1059.001 | 1 | 65 (High) |
| 2 | Discovery | Recursive enumeration of sensitive folders, `whoami`, `net user` | T1083, T1087.001 | 1 | 45 (Medium) |
| 3 | Collection | `Compress-Archive` into a staging folder such as `C:\Users\Public` | T1560.001, T1074.001 | 1, 11 | 70 (High) |
| 4 | Persistence | Registry Run key pointing to a PowerShell script | T1547.001 | 13 | 80 (High) |
| 5 | Exfiltration | Outbound web request from PowerShell to an external host | T1041, T1071.001 | 3 | 78 (High) |
| 6 | Defense evasion / Impact | Recursive deletion of project files and staging archive | T1070.004, T1070.001, T1485 | 1, 23 | 72 (High) |

## How the rules work

- **Single-event rules** (Phases 1, 2, 4, 5) match one telltale event, then filter out known-good context.
- **Mini-sequences** (Phases 3 and 6) use EQL `sequence` to require two related events: for example, a PowerShell archive command followed by an actual archive file appearing in a staging path, or a recursive `Remove-Item` followed by real file deletion events.
- **Kill-chain correlation** requires all six phases, in order, from the same user on the same host.

### Correlation rule

```eql
sequence by host.name, user.name with maxspan=2h
  [process where event.type == "start" and process.name == "powershell.exe"
     and process.command_line like~ ("*-ExecutionPolicy Bypass*", "*-ep bypass*",
         "*-EncodedCommand*", "*-WindowStyle Hidden*")]            /* 1 Execution */
  [process where event.type == "start" and process.name == "powershell.exe"
     and process.command_line like~ "*Get-ChildItem*"
     and process.command_line like~ "*-Recurse*"]                  /* 2 Discovery */
  [process where event.type == "start" and process.name == "powershell.exe"
     and process.command_line like~ "*Compress-Archive*"]          /* 3 Collection */
  [registry where event.type == "change"
     and registry.path like~ "*\\CurrentVersion\\Run\\*"
     and registry.data.strings like~ ("*powershell*", "*cmd.exe*",
         "*wscript*", "*.ps1*", "*.bat*")]                         /* 4 Persistence */
  [network where event.type == "start" and process.name == "powershell.exe"
     and destination.port in (80, 443, 8080, 8443)]                /* 5 Exfiltration */
  [process where event.type == "start" and process.name == "powershell.exe"
     and process.command_line like~ "*Remove-Item*"
     and process.command_line like~ "*-Recurse*"]                  /* 6 Defense evasion */
```

Design decisions:

- **Group by both `host.name` and `user.name`.** Grouping by host alone could match user A's discovery with user B's archive; grouping by user alone loses the location context.
- **`maxspan=2h`.** My first setting of 30 minutes was too short for a careful insider who pauses between steps; 24 hours was too wide on shared machines.
- **Outcome:** the rule is designed to raise a single Critical alert (risk score 99) carrying the whole chain and its MITRE mapping, so an analyst can go straight to containment.

## False-positive reduction

| Technique | Likely benign source | How the rule handles it |
|---|---|---|
| PowerShell bypass flags | IT maintenance scripts, SCCM, installers | Exclude trusted parents (`msiexec.exe`, `svchost.exe`, `services.exe`, `ccmexec.exe`, task hosts) and `Program Files` paths |
| Directory enumeration | File managers, indexing, backup tools | Require `-Recurse` plus a sensitive path or file type; exclude `explorer.exe`, `SearchIndexer.exe`, OneDrive |
| Archive creation | Backup software, OneDrive | Require a staging location and an archive file actually created there |
| Registry Run key | Software installers, common apps | Require a script interpreter in the value; exclude known entries (OneDrive, Teams, SecurityHealth...) and `Program Files` / `System32` targets |
| Outbound web request | Windows Update, telemetry, package feeds | Egress only, exclude private IP ranges and Microsoft, Windows Update and PowerShell Gallery domains |
| File deletion | Normal temp-file cleanup | Require recursion, a sensitive path and confirmed deletion events |

## Testing

- **Per-phase tests** with several variants: encoded commands, hidden windows, scripts launched from a staging folder, the .NET `ZipFile` class instead of `Compress-Archive`, the `iwr` alias, and `WebClient`.
- **Negative tests** that must *not* alert: a Run key pointing to a `Program Files` application, a request to a Microsoft domain, a connection to an internal IP, and deleting an ordinary temp file.
- **Full kill-chain simulation:** a script that runs all six phases back to back on the endpoint, used to exercise the correlation rule.

## Challenges and lessons learned

- **Sysmon EID 23 (File Delete) is not enabled by default.** I had to add it manually, otherwise the Phase 6 rule can never match. Lesson: verify the required event IDs exist before writing a rule.
- **Index pattern mismatch.** Elastic Agent writes to `logs-windows.sysmon_operational-*` while my rules pointed at a different pattern, so rules ran without ever producing alerts. Always test the query in Kibana Discover first.
- **ECS mapping is not automatic for every Sysmon field.** I checked the real field names in Discover before relying on them.
- **Discovery is the noisiest phase.** `Get-ChildItem` is used constantly, so this rule needed several tuning rounds.
- **Logging everything backfires.** Too much telemetry raises storage cost and causes alert fatigue, so filtering belongs in the Sysmon config.
- **Cloud testing limits.** Some Phase 5 tests need real outbound internet access, which AWS security group rules restricted.

## Next steps

- User behavior analytics with Elastic ML to baseline normal activity
- Lateral movement detection (WMI, PSRemoting)
- SOAR automation for response
- DNS monitoring with Sysmon EID 22 to catch DNS-based exfiltration
- Asset-criticality scoring to prioritise alerts
