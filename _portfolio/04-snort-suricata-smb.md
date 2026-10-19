---
title: "Deploying and Tuning Snort/Suricata IDS/IPS for SMB Networks"
excerpt: "A planned project to deploy and tune an open-source IDS/IPS for a small or medium business network. Currently at the research and design stage; no implementation yet."
collection: portfolio
status: planned
tools: ["Snort", "Suricata", "IDS/IPS", "pfSense", "Elastic SIEM"]
order: 4
---

**Planned project · Research and design stage**

> **Status:** nothing has been deployed yet. This page describes what I plan to build and the concepts behind it, and it will be updated with real results as the work progresses.

## Why this project

Small and medium businesses face the same network threats as large ones but rarely have a dedicated security team or an expensive commercial appliance. Open-source network IDS/IPS engines can fill that gap, but a default installation is usually either silent (no useful rules) or overwhelming (thousands of low-value alerts). The valuable skill is getting from a default install to a **tuned, maintainable** deployment.

## Background

**IDS versus IPS.** An intrusion detection system (IDS) inspects a copy of the traffic and raises alerts. An intrusion prevention system (IPS) sits *in line* and can drop malicious packets. Inline operation prevents more but adds risk: a bad rule or a failed sensor can break legitimate traffic, so it needs careful testing.

**Snort and Suricata.** Both are widely used open-source engines that match traffic against signature rules, and both can run in IDS or IPS mode.

| | Snort | Suricata |
|---|---|---|
| Threading | Snort 3 is multi-threaded (Snort 2 was single-threaded) | Multi-threaded by design |
| Rule format | Snort rule syntax | Largely compatible syntax with extensions |
| Structured logging | Alerts in several formats | Native EVE JSON output, convenient for SIEMs |

**Rule sources.** Commonly used rulesets include the Snort Community rules and the Emerging Threats (ET) Open rules; commercial subscriptions add faster updates.

## Planned scope

- **Target:** a typical SMB network with a firewall, a LAN, a few servers and user workstations
- **Placement:** compare passive (SPAN or tap) deployment against inline IPS, and decide where the sensor belongs relative to the firewall
- **Engines:** deploy both Snort and Suricata and compare them on the same traffic
- **SIEM integration:** forward alerts to my existing Elastic SIEM setup for triage

## Planned method

1. **Baseline:** capture normal traffic to learn what the network looks like
2. **Initial deployment** in IDS mode with a standard ruleset
3. **Tuning:** suppress or threshold noisy rules, disable categories that do not apply, and enable rules relevant to the assets present
4. **Testing:** replay captured traffic and generate known attack patterns (scans, exploit attempts) to check what is detected
5. **Move to IPS mode** only for high-confidence rules, with a fallback plan if traffic breaks
6. **Document** a maintenance routine: rule updates, review of alerts, and periodic re-tuning

## How I plan to measure it

- Alert volume before and after tuning
- False-positive rate on normal traffic
- Detection rate against a defined set of test attacks
- CPU, memory and throughput impact on modest hardware

## Prerequisites I already have

Hands-on experience with pfSense firewall and IDS/IPS concepts, with Elastic SIEM and Sysmon-based detection engineering (see my other projects), and with PCAP analysis in Wireshark.
