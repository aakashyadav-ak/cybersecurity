# 1: Understanding L1 vs L2 vs L3 Responsibilities

## SOC (Security Operations Center)
A SOC is a centralized team that monitors, detects, analyzes, and responds to cybersecurity threats 24/7.

Think of it like a security control room for an organization's IT infrastructure.

## SOC Analyst Tiers 

**Most SOCs follow a tier model:**
- L1 → Monitoring & Triage
- L2 → Investigation & Containment
- L3 → Threat Hunting & Advanced Analysis

#### SOC L1 Analyst (Tier 1) - "The First Responder"
**Key Responsibilities:**
✅ Monitor security alerts from SIEM, EDR, IDS/IPS, firewalls
✅ Initial triage – Is this alert real or false?
✅ Basic investigation – Check logs, user activity, IP reputation
✅ Categorize and prioritize alerts (High/Medium/Low)
✅ Escalate complex issues to L2
✅ Document findings in ticketing system
✅ Follow playbooks/SOPs (Standard Operating Procedures)

**Example Tasks:**
- An antivirus alert fires → Check if it's a known false positive
- User locked out → Check for brute force attempts
- Suspicious login from foreign country → Verify with user/manager

**Skills Needed:**
- Basic understanding of networks, operating systems
- Familiarity with security tools (SIEM basics)
- Good communication (you'll escalate a lot!)
- Attention to detail


#### SOC L2 Analyst (Tier 2) - "The Investigator"

**Key Responsibilities:**
✅ Deep-dive investigations – Analyze escalated incidents from L1
✅ Correlation analysis – Connect multiple alerts to find attack patterns
✅ Threat hunting – Proactively search for hidden threats
✅ Recommend remediation – Block IPs, isolate hosts, reset passwords
✅ Tune SIEM rules – Reduce false positives
✅ Mentor L1 analysts

**Example Tasks:**
L1 escalates suspicious PowerShell execution → You analyze process tree, parent-child relationships
Multiple failed logins + unusual network traffic → You identify a credential stuffing attack


#### SOC L3 Analyst / Incident Responder (Tier 3) - "The Expert"
Advanced role (3+ years experience)

Key Responsibilities:
✅ Handle critical incidents (ransomware, data breaches)
✅ Malware analysis (reverse engineering)
✅ Forensic investigation – Preserve evidence, root cause analysis
✅ Develop detection rules and playbooks
✅ Threat intelligence integration
✅ Coordinate with management and external teams (legal, law enforcement)


| Aspect | L1 | L2 | L3 |
| :--- | :--- | :--- | :--- |
| **Focus** | Monitoring & Triage | Investigation & Analysis | Incident Response & Forensics |
| **Alert Handling** | First look, quick checks | Deep analysis | Critical incidents only |
| **Decision Making** | Follow playbooks | Some autonomy | Full authority |
| **Escalation** | Escalates to L2 | Escalates to L3 | Final decision maker |
| **Experience** | 0-1 year | 1-3 years | 3+ years |

### Example
**Scenario:** You receive an alert:
"Antivirus detected: Trojan.Generic.12345 on LAPTOP-HR-05"

As L1, what would you do?
- Check if file is quarantined
- Look up file hash on VirusTotal
- Check user's recent activity (any suspicious downloads?)
- Verify with user if they downloaded anything unusual
- If confirmed malicious → Escalate to L2 + isolate machine
- If false positive → Document and close ticket


____


# 2: Alert Lifecycle (Alert → Triage → Investigate → Action → Document → Close)

## Alert Lifecycle
The alert lifecycle is the step-by-step process a SOC analyst follows from the moment an alert fires until it's resolved.

Think of it as a workflow/checklist that ensures no alert is missed and every incident is handled properly.

### The 6 Stages of Alert Lifecycle
```
📍 ALERT → 🔍 TRIAGE → 🕵️ INVESTIGATE → ⚡ ACTION → 📝 DOCUMENT → ✅ CLOSE
```

#### Stage 1: ALERT (Detection)
- A security tool (SIEM, EDR, Firewall, IDS/IPS) detects suspicious activity
- Alert appears in your dashboard/queue

- Example Alerts:
- "Multiple failed login attempts detected"
- "Malware detected: LAPTOP-FIN-12"
- "Outbound connection to known malicious IP"
- "Privilege escalation attempt on server"

**Your first action:**
✅ Acknowledge the alert (so other analysts know you're handling it)

#### Stage 2: TRIAGE (Initial Assessment)
Quickly determine if the alert is real and how urgent it is.

**Key Questions to Ask:**
❓ Is this a True Positive or False Positive?
❓ What is the severity? (Critical/High/Medium/Low)
❓ Is this a known issue (e.g., recurring false positive)?
❓ Is the affected system critical? (e.g., domain controller, database server)

**Quick Checks:**
✅ Check recent tickets – Has this happened before?
✅ Check whitelists/blacklists – Is the IP/domain known?
✅ Check user context – Is the user traveling? Working odd hours?
✅ Check asset criticality – Server vs employee laptop?

**Example Triage:**

| Alert | Quick Check | Decision |
| :--- | :--- | :--- |
| "Antivirus blocked file" | File already quarantined, no execution | Low priority, monitor |
| "Failed logins from China" | User is in US, never travels | **HIGH PRIORITY** → Investigate |
| "Port scan detected" | From vulnerability scanner IP (internal tool) | False Positive → Close |

**Outcome of Triage:**
✅ Proceed to Investigation (if suspicious)
✅ Close as False Positive (if benign)
✅ Escalate immediately (if critical and beyond L1 scope)

#### Stage 3: INVESTIGATE (Deep Dive)
Gather evidence to understand what happened, when, and why.

**Investigation Checklist:**
##### A) Timeline Analysis

🕐 When did it start?
🕐 Is it still ongoing?
🕐 What happened before/after?

##### B) User/Entity Analysis

👤 Who is the user? (Check AD, HR records)
💼 What is their role? (Finance, HR = higher risk)
📞 Contact user/manager to verify activity.

##### C) Log Analysis (Most important!)

🖥️ Windows Event Logs (Login events, process creation)
🌐 Firewall logs (Incoming/outgoing connections)
🔐 Proxy logs (Websites visited)
📧 Email gateway logs (Phishing attempts?)

##### D) Threat Intelligence

🔗 Check IP/domain reputation (VirusTotal, AbuseIPDB)
🔗 Check file hash (VirusTotal, Hybrid Analysis)
🔗 Search for IOCs (Indicators of Compromise)

###### Example Investigation:
**Alert:** "Suspicious PowerShell execution on LAPTOP-HR-08"

**Investigation Steps:**

1. Check what PowerShell command was run.
```
powershell.exe -enc <base64_encoded_command>
```

(Encoded commands = red flag! 🚩)

2. Decode the command (use CyberChef)

- If it downloads malware → True Positive
- If it's a legitimate admin script → Check with IT team

3. Check process tree (parent-child processes)

- Was it launched by winword.exe (Word)? → Likely macro malware
- Was it launched by explorer.exe? → User clicked something

4. Check network connections (Did it connect to external IP?)

5. Check user activity (Any other suspicious actions?)

**Outcome:**

✅ Confirmed malicious → Move to Action
✅ Confirmed benign → Move to Document & Close
✅ Need expert help → Escalate to L2


#### Stage 4: ACTION (Containment & Remediation)
**Goal:** Stop the threat and prevent damage.

#### Common Actions (L1 Level):

| Threat Type | Action |
| :--- | :--- |
| Malware detected | Isolate machine from network, run full scan |
| Compromised account | Disable account, force password reset |
| Malicious IP connection | Block IP at firewall, check other systems |
| Phishing email | Delete email from all inboxes, block sender |
| Insider threat | Escalate to L2 + notify management |

**Important Notes:**
- ⚠️ Always follow your playbook – Don't improvise on critical systems
- ⚠️ Get approval for major actions – Blocking a server can disrupt business
- ⚠️ Preserve evidence – Don't delete logs/files (needed for forensics)

**Example Action:**
- Scenario: Confirmed ransomware on LAPTOP-FIN-12
- **Your action:**
	1. Immeiately isolate the laptop (disconnect network)
	2. Notify L2/Incident Response team
	3. Check backups (with IT team)
	4. Scan network for lateral movement



#### Stage 5: 📝 DOCUMENT (Record Everything)
**Goal:** Create a clear record for future reference and compliance.

**What to Document:**
✅ Alert Details
Alert name, timestamp, source system

✅ Investigation Summary
What you checked, what you found

✅ Evidence
Screenshots, log excerpts, file hashes, IPs

✅ Actions Taken
What you did to contain/remediate

✅ Outcome
True Positive / False Positive
Resolved / Escalated

**Example Ticket Documentation:**
```
TICKET #12345: Malware Detection - LAPTOP-HR-08

SUMMARY:
Antivirus detected Trojan.Generic on LAPTOP-HR-08 at 14:35 UTC.

INVESTIGATION:
- File: invoice.exe (downloaded from suspicious email)
- Hash: 5d41402abc4b2a76b9719d911017c592
- VirusTotal: 45/70 vendors flagged as malicious
- User confirmed clicking email attachment

ACTIONS TAKEN:
- Isolated machine from network
- Ran full antivirus scan (3 additional files quarantined)
- Reset user password
- Blocked sender domain at email gateway

OUTCOME:
TRUE POSITIVE - Malware removed, system cleaned.

STATUS: CLOSED
```


#### Stage 6: ✅ CLOSE (Resolution)
**Goal:** Officially close the ticket after confirming the issue is resolved.

**Before Closing, Verify:**
- ✅ Threat is fully contained/removed
- ✅ System is back to normal operation
- ✅ User notified (if applicable)
- ✅ Documentation is complete
- ✅ Follow-up actions assigned (if any)

**Closure Categories:**
- ✅ True Positive - Resolved
- ✅ False Positive - No Action Needed
- ✅ Escalated to L2/L3
- ✅ Pending (waiting for user/IT team)
