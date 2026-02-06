# SOC Analyst - Endpoint Security Syllabus Checklist

---

## Overview

> [!info] Course Information
> - **Total Modules:** 12
> - **Total Lessons:** 100+
> - **Hands-On Labs:** 10
> - **Estimated Time:** 8-10 weeks
> - **Focus:** SOC Analyst Role

---

## TIER 1: CRITICAL (Must Know First)

### Module 01: SIEM Fundamentals & Operations
- [ ] Lesson 01: What is SIEM and Why SOC Needs It
- [ ] Lesson 02: SIEM Architecture & Components
- [ ] Lesson 03: Log Sources (Windows, Linux, Network, Application)
- [ ] Lesson 04: Log Collection & Ingestion
- [ ] Lesson 05: Log Parsing & Normalization
- [ ] Lesson 06: Creating Detection Rules & Alerts
- [ ] Lesson 07: Alert Triage & Investigation
	      
	      
	- [ ] Lesson 08: Dashboard Creation & Visualization
	- [ ] Lesson 09: Use Cases & Correlation Rules
	- [ ] Lesson 10: Alert Tuning & False Positive Reduction
	- [ ] Lesson 11: Popular SIEM Tools (Splunk, QRadar, Sentinel, ELK)
	- [ ] Lesson 12: SIEM Best Practices

### Module 02: EDR/XDR Operations
- [ ] Lesson 01: Antivirus vs EPP vs EDR vs XDR
- [ ] Lesson 02: How EDR Works (Architecture)
- [ ] Lesson 03: EDR Detection Methods
- [ ] Lesson 04: EDR Alert Types & Severity
- [ ] Lesson 05: Alert Triage & Investigation in EDR
- [ ] Lesson 06: Endpoint Isolation & Containment
		- [ ] Lesson 07: Threat Hunting with EDR
		- [ ] Lesson 08: IOC vs IOA Analysis
		- [ ] Lesson 09: Common EDR Tools (CrowdStrike, Defender, SentinelOne, Carbon Black)
		- [ ] Lesson 10: EDR + SIEM Integration
		- [ ] Lesson 11: XDR Concepts & Benefits

### Module 03: MITRE ATT&CK Framework
- [ ] Lesson 01: Introduction to MITRE ATT&CK
- [ ] Lesson 02: Understanding the Matrix
- [ ] Lesson 03: Tactics (14 Categories Explained)
- [ ] Lesson 04: Techniques & Sub-Techniques
- [ ] Lesson 05: Mapping Alerts to MITRE ATT&CK
		- [ ] Lesson 06: Using ATT&CK for Detection Engineering
		- [ ] Lesson 07: ATT&CK Navigator Tool
		- [ ] Lesson 08: Threat Hunting with ATT&CK
		- [ ] Lesson 09: Common Attack Patterns (Kill Chain Mapping)
		- [ ] Lesson 10: ATT&CK-Based Reporting

### Module 04: Incident Response Fundamentals
- [ ] Lesson 01: What is Incident Response
- [ ] Lesson 02: IR Lifecycle (NIST/SANS Framework)
- [ ] Lesson 03: Incident Classification & Severity Levels
- [ ] Lesson 04: Alert Triage Process
- [ ] Lesson 05: Initial Analysis & Scoping
- [ ] Lesson 06: Containment Strategies
		- [ ] Lesson 07: Evidence Collection & Preservation
		- [ ] Lesson 08: Eradication & Recovery
		- [ ] Lesson 09: Post-Incident Analysis & Lessons Learned
		- [ ] Lesson 10: Incident Documentation & Reporting
		- [ ] Lesson 11: Communication During Incidents

---

## TIER 2: IMPORTANT (Learn Second)

### Module 05: Log Analysis
- [ ] Lesson 01: Importance of Log Analysis
- [ ] Lesson 02: Windows Event Logs (Security, System, Application)
- [ ] Lesson 03: Critical Windows Event IDs for SOC
- [ ] Lesson 04: Linux Logs (auth.log, syslog, secure)
- [ ] Lesson 05: Network Device Logs (Firewall, Router, Switch)
		- [ ] Lesson 06: Web Server Logs (Apache, Nginx, IIS)
		- [ ] Lesson 07: Application & Database Logs
		- [ ] Lesson 08: Log Analysis Techniques & Patterns
		- [ ] Lesson 09: Timeline Analysis

### Module 06: Network Security Fundamentals
- [ ] Lesson 01: Network Security Basics for SOC
- [ ] Lesson 02: Firewall Types & Rule Analysis
- [ ] Lesson 03: IDS/IPS Concepts & Alert Types
- [ ] Lesson 04: Network Traffic Analysis Basics
- [ ] Lesson 05: Common Network Attacks (DDoS, MITM, etc.)
- [ ] Lesson 06: Reading Firewall & IDS Logs
- [ ] Lesson 07: Network Segmentation & Zones
- [ ] Lesson 08: VPN & Remote Access Security

### Module 07: Malware Analysis Basics
- [ ] Lesson 01: Malware Types (Virus, Trojan, Ransomware, etc.)
- [ ] Lesson 02: Malware Behavior Patterns
- [ ] Lesson 03: Static vs Dynamic Analysis
- [ ] Lesson 04: Using Sandboxes (Any.Run, Joe Sandbox, Hybrid Analysis)
- [ ] Lesson 05: VirusTotal & Other Reputation Tools
		- [ ] Lesson 06: Identifying Malicious Indicators
		- [ ] Lesson 07: Safe Malware Handling Procedures
		- [ ] Lesson 08: Documenting Malware Findings

### Module 08: Threat Intelligence
- [ ] Lesson 01: What is Threat Intelligence
- [ ] Lesson 02: Types of Threat Intelligence (Strategic, Tactical, Operational)
- [ ] Lesson 03: IOC Types (Hash, IP, Domain, URL, Email)
- [ ] Lesson 04: Threat Intel Platforms (MISP, OTX, ThreatConnect)
- [ ] Lesson 05: Using Threat Intel in SOC Operations
- [ ] Lesson 06: Threat Actor Profiles & TTPs
- [ ] Lesson 07: Intelligence-Driven Detection

---

## TIER 3: GOOD TO KNOW

### Module 09: Email Security
- [ ] Lesson 01: Email Threats Overview (Phishing, BEC, Spam)
- [ ] Lesson 02: Phishing Analysis Techniques
- [ ] Lesson 03: Email Header Analysis
- [ ] Lesson 04: Attachment & URL Analysis
- [ ] Lesson 05: Email Security Tools (Proofpoint, Mimecast, O365)
- [ ] Lesson 06: Reporting Phishing Incidents

### Module 10: APT & Advanced Threats
- [ ] Lesson 01: What is Advanced Persistent Threat (APT)
- [ ] Lesson 02: APT Lifecycle & Progression
- [ ] Lesson 03: Famous APT Groups & Their TTPs
- [ ] Lesson 04: Detecting APT Activity
- [ ] Lesson 05: APT Hunting Techniques
- [ ] Lesson 06: Defense Strategies Against APT

### Module 11: Data Loss Prevention (DLP)
- [ ] Lesson 01: DLP Concepts & Why It Matters
- [ ] Lesson 02: Types of DLP (Network, Endpoint, Cloud)
- [ ] Lesson 03: DLP Alert Types
- [ ] Lesson 04: Investigating Data Exfiltration
- [ ] Lesson 05: DLP Policy Management

### Module 12: SOC Operations & Soft Skills
- [ ] Lesson 01: SOC Structure & Roles (L1, L2, L3)
- [ ] Lesson 02: Shift Handover Procedures
- [ ] Lesson 03: Ticketing & Case Management
- [ ] Lesson 04: SLA & Metrics (MTTD, MTTR)
- [ ] Lesson 05: Effective Communication & Escalation
- [ ] Lesson 06: Report Writing for SOC
- [ ] Lesson 07: Continuous Learning & Staying Updated

---

## BONUS: Hands-On Labs

### Lab Module: Practical Exercises
- [ ] Lab 01: Splunk Basics - Search & Investigation
- [ ] Lab 02: ELK Stack - Log Analysis
- [ ] Lab 03: Windows Event Log Investigation
- [ ] Lab 04: EDR Alert Triage (Defender/CrowdStrike)
- [ ] Lab 05: Malware Sandbox Analysis
- [ ] Lab 06: Phishing Email Analysis
- [ ] Lab 07: Network Traffic Analysis (Wireshark Basics)
- [ ] Lab 08: MITRE ATT&CK Mapping Exercise
- [ ] Lab 09: Incident Response Simulation
- [ ] Lab 10: Threat Hunting Exercise

---

## Progress Tracker

> [!summary] Completion Status
> 
> | Tier | Modules | Completed | Progress |
> |------|---------|-----------|----------|
> | TIER 1 | 4 | 0/4 | 0% |
> | TIER 2 | 4 | 0/4 | 0% |
> | TIER 3 | 4 | 0/4 | 0% |
> | Labs | 10 | 0/10 | 0% |
> | **TOTAL** | **12 + Labs** | **0** | **0%** |

---
## Quick Reference

> [!important] Priority Topics for Interview
> 
> **MUST KNOW:**
> - SIEM concepts & log analysis
> - EDR alert triage
> - MITRE ATT&CK tactics & techniques
> - Incident response steps
> - Common Windows Event IDs
> - Malware types & behavior
> - Phishing analysis
> 
> **TOOLS TO LEARN:**
> - Splunk / ELK
> - CrowdStrike / Microsoft Defender
> - VirusTotal / Any.Run
> - Wireshark (basics)
> - MITRE ATT&CK Navigator

---