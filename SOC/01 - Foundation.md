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