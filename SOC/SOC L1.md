# SOC L1 Analyst

**Focus:** Detection • Triage • Investigation • Documentation • Cloud  

---

## 1) SOC OPERATIONS (Foundation)
- [x] Understand L1 vs L2 vs L3 responsibilities
- [x] Understand alert lifecycle (Alert → Triage → Investigate → Action → Document → Close)
- [x] Know when to Escalate vs Close
- [x] Understand True Positive / False Positive / False Negative
- [ ] Understand Severity levels (P1–P4) & SLA
- [ ] Write proper incident ticket (Summary, Evidence, Action, Recommendation)

---

## 2) FRAMEWORKS (Interview Mandatory)
- [ ] Explain MITRE ATT&CK (Tactic vs Technique)
- [ ] **Map these 4 Attacks:**
  - [ ] Brute Force → T1110
  - [ ] Phishing → T1566
  - [ ] PowerShell → T1059.001
  - [ ] Credential Dumping → T1003
- [ ] Explain Cyber Kill Chain stages
- [ ] Explain Pyramid of Pain (Hash vs TTP)
- [ ] Memorize NIST IR lifecycle (PICERL)
- [ ] Explain CIA Triad with real examples

---

## 3) WINDOWS DETECTION (MOST IMPORTANT)
### Critical Event IDs
- [ ] `4624` – Successful Logon
- [ ] `4625` – Failed Logon
- [ ] `4688` – Process Creation (Command Line)
- [ ] `4720` – User Created
- [ ] `4732` – Added to Admin Group
- [ ] `4769` – Kerberos Service Ticket
- [ ] `7045` – Service Created
- [ ] `1102` – Log Cleared
- [ ] `4104` – PowerShell Script Block

### Must Detect
- [ ] Brute force (multiple 4625 + 1 success)
- [ ] Password spraying pattern
- [ ] Suspicious PowerShell (`-enc`, `IEX`, `DownloadString`)
- [ ] New admin account creation
- [ ] Log clearing attempt

---

## 4) LINUX DETECTION
- [ ] Analyze `/var/log/auth.log` or `/var/log/secure`
- [ ] Detect SSH brute force
- [ ] Detect sudo abuse
- [ ] Detect cron persistence
- [ ] Detect reverse shell patterns
- [ ] Detect web shell in web directory

---

## 5) SIEM SKILLS (CORE HIRING FILTER)
### Concepts
- [ ] Log collection → Normalization → Correlation → Alerting

### Splunk (Minimum)
- [ ] Write search query
- [ ] `stats count by`
- [ ] `table`
- [ ] `dedup`
- [ ] `timechart`
- [ ] Create threshold alert

### KQL (Cloud SOC Standard - 2026 Critical)
- [ ] Filter EventID: `SecurityEvent | where EventID == 4625`
- [ ] Aggregation: `| summarize count() by Account`
- [ ] Filter by threshold: `| where count_ > 50`
- [ ] Project specific columns

---

## 6) EDR / XDR INVESTIGATION
- [ ] Understand EDR vs XDR
- [ ] Analyze process tree
- [ ] Identify suspicious parent-child (`Word` → `PowerShell`)
- [ ] Identify process running from `Temp` or `AppData`
- [ ] Detect LOLBins:
  - [ ] `powershell.exe -enc`
  - [ ] `certutil.exe -urlcache`
  - [ ] `mshta.exe`
  - [ ] `rundll32.exe`
- [ ] Understand "Isolate Host" action

---

## 7) EMAIL & PHISHING (DAILY TASK)
- [ ] Analyze email headers (SPF/DKIM/DMARC)
- [ ] Extract sender IP from `Received` headers
- [ ] Identify spoofed domain
- [ ] Check attachment hash in VirusTotal
- [ ] Analyze URL safely (**URLScan.io**)
- [ ] **Sandboxing:** Detonate file in **Any.Run** or **Hybrid Analysis**
- [ ] Differentiate Spam vs Malicious

---

## 8) CLOUD LOGS (NON-NEGOTIABLE)
### Azure / Entra ID
- [ ] Analyze sign-in logs
- [ ] Detect **Impossible Travel**
- [ ] Detect **MFA Fatigue**
- [ ] Detect OAuth abuse
- [ ] Detect mailbox rule persistence

### AWS (Awareness Level)
- [ ] CloudTrail login events
- [ ] Root account usage
- [ ] New IAM key creation
- [ ] Public S3 bucket detection

---

## 9) NETWORK TRIAGE
- [ ] Detect port scanning
- [ ] Detect **Beaconing** (regular interval traffic)
- [ ] Detect large outbound transfer (exfiltration)
- [ ] Understand critical ports (22, 53, 80, 443, 445, 3389)
- [ ] Use Wireshark filters
- [ ] Understand DNS tunneling basics

---

## 10) THREAT INTELLIGENCE
- [ ] Lookup IP/Domain/Hash in VirusTotal
- [ ] Check AbuseIPDB
- [ ] Understand IOC lifespan
- [ ] Understand difference between IOC & TTP
- [ ] Use GreyNoise to identify scanners

---

## 11) ATTACK SCENARIOS (YOU MUST DETECT)
- [ ] Brute Force / Password Spraying
- [ ] MFA Bombing
- [ ] Kerberoasting
- [ ] Ransomware indicators
- [ ] C2 beaconing
- [ ] Lateral movement (PsExec / RDP)
- [ ] Data exfiltration pattern
- [ ] Living off the Land abuse

---

## 12) AUTOMATION (YOUR EDGE)
- [ ] Write Python script for IP reputation lookup
- [ ] Parse Windows logs using Python
- [ ] Understand SOAR playbooks
- [ ] Understand automated IP blocking workflow

---

## 13) PORTFOLIO (THE HIRED MAKER)
- [ ] 1 Brute Force investigation write-up
- [ ] 1 Phishing investigation write-up
- [ ] 1 SIEM dashboard project
- [ ] GitHub repo with scripts
- [ ] LinkedIn post explaining a detection concept

---

## 🏆 FINAL SELF-TEST
- [ ] I can confidently answer scenario-based questions
- [ ] I can investigate an alert end-to-end
- [ ] I can write a professional incident report
- [ ] I can explain everything in simple language
- [ ] I am comfortable working in a 24/7 SOC shift

____
🧠 1️⃣ MUST MEMORIZE (Non-Negotiable)

These are rapid-fire interview questions.

🔹 Frameworks (Section 2)

Memorize:

MITRE ATT&CK definition (Tactic vs Technique)

These mappings:

Brute Force → T1110

Phishing → T1566

PowerShell → T1059.001

Credential Dumping → T1003

NIST IR lifecycle (PICERL)

CIA Triad (with examples)

Cyber Kill Chain stages

Pyramid of Pain concept

👉 These are “Tell me in 30 seconds” questions.

🔹 Critical Windows Event IDs (Section 3)

Memorize meanings of:

4624

4625

4688

4720

4732

4769

7045

1102

4104

You should instantly respond when interviewer says:
“What is 4625?”

🔹 Common Ports (Section 9)

Memorize:
22, 53, 80, 443, 445, 3389

Very common question:
“What port does RDP use?”

🔬 2️⃣ MUST UNDERSTAND DEEPLY (Concept + Scenario)

These are NOT memorization topics.
These are “explain how” topics.

🔥 A) Windows Detection (Most Important)

You must deeply understand:

How brute force looks in logs

Password spraying difference

Suspicious PowerShell patterns

Admin account creation detection

Log clearing detection

Interview Question:
“If you see 100 failed logins and then one success, what will you do?”

If you only memorize 4625 — you fail.
If you explain triage steps — you pass.

🔥 B) Cloud Logs (VERY HOT IN 2026)

Deep understanding needed:

Impossible travel logic

MFA fatigue behavior

Mailbox rule persistence

OAuth abuse basics

Modern SOC = identity-focused.

If you skip this → you are outdated.

🔥 C) EDR Investigation

You must understand:

Process tree analysis

Parent-child relationship

LOLBins behavior

Why Word → PowerShell is suspicious

What “Isolate Host” actually does

Interview question:
“What would you check in EDR if you receive ransomware alert?”

🔥 D) Attack Scenarios (Section 11)

This is CRITICAL.

You must deeply understand:

Kerberoasting logic

Lateral movement detection

Beaconing detection logic

Data exfiltration patterns

Living off the land abuse

Scenario-based interviews dominate 2026 hiring.

🛠 3️⃣ MUST PRACTICE HANDS-ON

These are practical filters:

🔹 SIEM (Section 5)

You must practice:

Splunk basic queries

KQL aggregation

Threshold filtering

You don't memorize syntax.
You practice it.

🔹 Email Analysis (Section 7)

You must practice:

Header reading

Hash lookup

URL analysis

SPF/DKIM basics

Interviewers LOVE phishing scenarios.

🔹 Threat Intelligence Tools

Know how to use:

VirusTotal

AbuseIPDB

GreyNoise

URLScan.io

ANY.RUN

Hybrid Analysis

You don’t memorize — you know how to use them.

🎯 4️⃣ MOST ASKED IN SOC L1 INTERVIEWS (2026 Reality)

Ranked by frequency:

🥇 #1 Windows Event Log Scenarios

Explain 4625 spike

Explain suspicious 4688

Explain log clearing

🥈 #2 Phishing Investigation

What will you check?

How to validate malicious email?

What if user clicked link?

🥉 #3 MITRE Mapping

Map brute force

Map PowerShell attack

Explain tactic vs technique

🏅 #4 EDR Alert

Word spawning PowerShell

Ransomware behavior

Process in Temp folder

🎖 #5 Cloud Identity Alert

Impossible travel

MFA fatigue

Suspicious sign-in

