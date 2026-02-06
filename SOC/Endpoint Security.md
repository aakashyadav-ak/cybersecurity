# SOC Checklist 

## Module 01: SIEM Essentials
- [x] 1.1 What is SIEM & Why SOC Needs It
- [x] 1.2 SIEM Architecture (Forwarders, Indexers, Search Heads)
- [x] 1.3 Log Sources (On-Prem vs **Cloud Logs like CloudTrail/Entra**)
- [x] 1.4 Alert Triage & Investigation Process
- [x] 1.5 False Positives & How to Reduce Them
- [x] 1.6 **SOAR & Playbooks** (How to automate triage via Python)
 - [x] What are IOCs (Hashes, IPs, Domains)
 - [x] Using TI platforms (VirusTotal, OTX, AbuseIPDB)
 - [ ] Understanding threat actor TTPs

---

## Module 02: EDR/XDR Fundamentals

- [ ] 2.1 Antivirus vs EPP vs EDR vs XDR
- [ ] 2.2 How EDR Works (Architecture & Kernel Visibility)
- [ ] 2.3 Alert Triage: Analyzing **Process Trees**
- [ ] 2.4 Endpoint Isolation & Containment
- [ ] 2.5 IOC vs IOA (Indicators of Compromise vs. Attack)
- [ ] 2.6 **ITDR (Identity Threat Detection & Response)** - Detecting MFA bypass.

---

## Module 03: MITRE ATT&CK Framework
- [ ] 3.1 What is MITRE ATT&CK & Why use it?
- [ ] 3.2 Understanding the Matrix Structure
- [ ] 3.3 14 Tactics Explained (Initial Access to Impact)
- [ ] 3.4 Mapping Alerts to MITRE Techniques
- [ ] 3.5 **Living off the Land (LOLBins)**: How attackers use legitimate tools (PowerShell/CMD).
		
---

## Module 04: Incident Response Basics

- [ ] 4.1 What is Incident Response?
- [ ] 4.2 IR Lifecycle (**NIST vs SANS** Frameworks)
- [ ] 4.3 Incident Classification & Severity Levels
- [ ] 4.4 Alert Triage Process
- [ ] 4.5 Containment Strategies (Isolation, Account Disable, IP Block)

---

## Module 05: Log Analysis 
>  Priority:  (Crucial for Interviews)
- [ ] 5.1 Windows Event Logs (Security, System, Application)
- [ ] 5.2 Critical Windows Event IDs (See Table Below)
- [ ] 5.3 **Logon Types** (Type 2, 3, 10 - Crucial for Interviews)
- [ ] 5.4 Linux Logs (auth.log, syslog)

| Event ID | Description | Why it matters? |
| :--- | :--- | :--- |
| **4624** | Successful Login | Check **Logon Type** (Type 10 = RDP!) |
| **4625** | Failed Login | High count = Brute Force / Spraying |
| **4688** | New Process Created | Detects `cmd.exe`, `powershell.exe` |
| **7045** | Service Installed | Persistence (Attacker making a backdoor) |
| **4672** | Admin Login | Check if a normal user suddenly got Admin |
| **1102** | Log Cleared | **RED ALERT** - Attacker hiding tracks |

---

## Module 06: Malware & Sandbox Analysis
- [ ] 6.1 Malware Types (Ransomware, Infostealers, RATs)
- [ ] 6.2 Malware Behavior Patterns (Registry changes, C2 connections)
- [ ] 6.3 Static vs Dynamic Analysis
- [ ] 6.4 Using VirusTotal & Sandbox Tools (Any.Run, Joe Sandbox)

---

## Module 07: Email & Identity Phishing
- [ ] 7.1 Email Threats (Phishing, BEC, **Quishing - QR Phishing**)
- [ ] 7.2 Phishing Analysis (Headers: SPF, DKIM, DMARC)
- [ ] 7.3 **Session Token Theft** (Detecting AitM / MFA Bypassing)

---

## Module 08: SOC Operations & Metrics
- [ ] 8.1 SOC Structure (L1/L2/L3)
- [ ] 8.2 Ticketing & Case Management
- [ ] 8.3 SLA & Metrics (**MTTD, MTTR**)
- [ ] 8.4 **AI Security Copilots** (Using AI to summarize logs)

---

## Hands-On Labs
- [ ] **Lab 01:** Splunk/Sentinel Search (Find a specific user's login history)
- [ ] **Lab 02:** Windows Event Analysis (Identify a Brute Force attack from a `.evtx` file)
- [ ] **Lab 03:** Phishing Investigation (Analyze an `.eml` file and check headers)
- [ ] **Lab 04:** Python Automation (Write a script to check an IP against the AbuseIPDB API)

---

> [!question] 
> 1. **"You see a successful login (4624) from a foreign IP, but the user has MFA. What happened?"** 
>    *Answer: Session Token Theft or MFA Fatigue.*
> 2. **"How do you tell a sysadmin apart from an attacker using PowerShell?"**
>    *Answer: Context & Parent Process (e.g., PowerShell spawned by Word is bad).*
> 3. **"What is the difference between Logon Type 2 and Type 10?"**
>    *Answer: Type 2 is Physical/Interactive. Type 10 is Remote (RDP).*
> 4. **"What is your first step when you confirm a Ransomware alert?"**
>    *Answer: Host Isolation via EDR.*
> 5. **"How would you use Python in this SOC role?"**
>    *Answer: Automating alert enrichment and IOC lookups via API.*

---

