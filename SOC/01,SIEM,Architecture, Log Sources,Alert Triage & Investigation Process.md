# SIEM = Security Information and Event Management

 It collects logs from everywhere in your organization, correlates them, and alerts you when something suspicious happens.
```
┌─────────────────────────────────────────────────────────────────┐
│                        SIEM OVERVIEW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   [Firewall Logs]──┐                                           │
│   [Server Logs]────┤                                           │
│   [EDR Alerts]─────┼──────►  [  SIEM  ]  ──────► [ALERTS]      │
│   [Cloud Logs]─────┤         (Correlate)         [DASHBOARDS]  │
│   [Email Logs]─────┘         (Analyze)           [REPORTS]     │
│                              (Store)                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## The Two Parts of SIEM:

| Component | What it does | Example |
| :--- | :--- | :--- |
| **SIM** (Security Information Management) | Long-term storage, compliance, and historical reporting. | "Generate a report of all admin logins from the last 6 months." |
| **SEM** (Security Event Management) | Real-time monitoring, event correlation, and instant alerting. | "Trigger an alert **NOW** if 10 failed logins happen within 1 minute." |
| **SIEM** (Combined) | The complete solution for both real-time detection and historical analysis. | "Alert me to a brute force attack (SEM) and store the logs for 1 year (SIM)." |

## Need of SIEM

#### Without SIEM:
```
Analyst: "I need to check if this IP attacked us"
         → Log into firewall... search...
         → Log into AD... search...
         → Log into web server... search...
         → 3 hours later... still searching
```

#### With SIENM:
```
Analyst: Search "src_ip=192.168.1.100"
         → All logs from all sources in ONE place
         → 30 seconds... done!
```

##  SIEM Capabilities
```
┌────────────────────────────────────────────────────────┐
│                  SIEM CAPABILITIES                      │
├──────────────────┬─────────────────────────────────────┤
│ Log Collection   │ Gather logs from 100s of sources   │
├──────────────────┼─────────────────────────────────────┤
│ Normalization    │ Convert all logs to common format  │
├──────────────────┼─────────────────────────────────────┤
│ Correlation      │ Connect related events together    │
├──────────────────┼─────────────────────────────────────┤
│ Alerting         │ Trigger alerts on suspicious       │
│                  │ patterns                           │
├──────────────────┼─────────────────────────────────────┤
│ Dashboards       │ Visualize security posture         │
├──────────────────┼─────────────────────────────────────┤
│ Retention        │ Store logs for compliance          │
│                  │ (90 days, 1 year, etc.)            │
└──────────────────┴─────────────────────────────────────┘
```


### Popular SIEM Tools 



| SIEM Tool | Type | Common In | 2026 Market Note |
| :--- | :--- | :--- | :--- |
| **Splunk** | Hybrid (On-Prem/Cloud) | Enterprise, Fortune 500 | Still the #1 "Power User" tool. Great for complex queries. |
| **Microsoft Sentinel** | Cloud-Native (SaaS) | Azure / Office 365 Shops | Rapidly growing due to easy integration with Windows/Azure. |
| **IBM QRadar** | Hybrid (On-Prem/Cloud) | Large Banks & Govt | Known for strong correlation and "Offense" management. |
| **Elastic SIEM (ELK)** | Open Source / Managed | Startups, Tech-focused | Fast and highly customizable; popular for "Big Data" logging. |
| **Google Chronicle** | Cloud-Native | Google Cloud (GCP) | Uses "Planet-scale" search; very fast at searching years of data. |
| **CrowdStrike LogScale** | Cloud-Native | Modern, High-Speed SOCs | Formerly Humio; built for massive ingest speeds and "Live" data. |


---
# SIEM Architecture
## Splunk

### Three-Tier Architecture:
```
┌─────────────────────────────────────────────────────────────────────┐
│                     SPLUNK ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │  FORWARDER  │───►│   INDEXER   │───►│ SEARCH HEAD │              │
│  │  (Collect)  │    │   (Store)   │    │  (Search)   │              │
│  └─────────────┘    └─────────────┘    └─────────────┘              │
│        │                  │                   │                      │
│        ▼                  ▼                   ▼                      │
│   Sits on the       Processes &         Where analysts              │
│   endpoint/server   indexes logs        run searches                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Component 
1. Forwarders (Data Collection)
   
```
   ┌─────────────────────────────────────────────────────────┐
│                    FORWARDER TYPES                       │
├───────────────────┬─────────────────────────────────────┤
│ Universal         │ Lightweight agent on endpoints      │
│ Forwarder (UF)    │ Just forwards raw logs              │
│                   │ Low CPU/memory usage                │
├───────────────────┼─────────────────────────────────────┤
│ Heavy Forwarder   │ Can parse/filter before sending     │
│ (HF)              │ Used at network edge                │
│                   │ Higher resource usage               │
├───────────────────┼─────────────────────────────────────┤
│ Syslog Input      │ Receives syslog from firewalls,     │
│                   │ network devices                     │
└───────────────────┴─────────────────────────────────────┘
```

2.  Indexers (Storage & Processing)
    Receives, parses, indexes, and stores logs. This is where your data lives.

```
   Raw Log:
"Mar 15 10:23:45 webserver sshd[12345]: Failed password for admin from 192.168.1.50"

         │
         ▼  [INDEXING PROCESS]
         
┌─────────────────────────────────────────────────────────┐
│  _time = 2024-03-15 10:23:45                           │
│  host = webserver                                       │
│  source = /var/log/auth.log                            │
│  sourcetype = syslog                                   │
│  _raw = "Failed password for admin from 192.168.1.50"  │
└─────────────────────────────────────────────────────────┘
         │
         ▼
    Stored in index (like a database)
```

3. Search Head (Query Interface)
   This is where the analyst work!
   
```sql
 -- Example Splunk Search (SPL)
index=security sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, user
| where count > 10
| sort -count
```

This search finds: Brute force attempts (more than 10 failed logins per IP/user)





---

# Log Sources (On-Prem vs Cloud)

## On-Premises Log Sources:

```
┌────────────────────────────────────────────────────────────────┐
│                    ON-PREM LOG SOURCES                          │
├────────────────────┬───────────────────────────────────────────┤
│ Windows Servers    │ Security, System, Application Event Logs │
├────────────────────┼───────────────────────────────────────────┤
│ Linux Servers      │ /var/log/auth.log, /var/log/syslog       │
├────────────────────┼───────────────────────────────────────────┤
│ Firewalls          │ Palo Alto, Fortinet, Cisco ASA logs      │
├────────────────────┼───────────────────────────────────────────┤
│ Active Directory   │ DC Security logs (4624, 4625, 4768...)   │
├────────────────────┼───────────────────────────────────────────┤
│ Proxy/Web Filter   │ Zscaler, BlueCoat, Squid logs            │
├────────────────────┼───────────────────────────────────────────┤
│ Email Gateway      │ Proofpoint, Mimecast logs                │
├────────────────────┼───────────────────────────────────────────┤
│ EDR                │ CrowdStrike, Defender, SentinelOne       │
└────────────────────┴───────────────────────────────────────────┘
```

## Cloud Log Sources
Critical cloud logs you MUST know:

**AWS**

CloudTrail (MUST) → Every API call (who logged into console, who launched EC2, etc.)
VPC Flow Logs → Network traffic
GuardDuty → Built-in threat detection
S3 Access Logs

**Azure**

Azure Activity Log → Control plane (who created a VM, changed RBAC)
Sign-in Logs (Entra ID) → Critical for identity attacks
NSG Flow Logs → Network
Microsoft Defender for Cloud alerts




---

# Alert Triage & Investigation Process

## The Triage Workflow:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ALERT TRIAGE WORKFLOW                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   [ALERT FIRES]                                                     │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────────┐                                                   │
│   │ 1. RECEIVE  │  Read the alert, understand what triggered       │
│   └──────┬──────┘                                                   │
│          ▼                                                          │
│   ┌─────────────┐                                                   │
│   │ 2. VALIDATE │  Is this real? Check for false positive          │
│   └──────┬──────┘                                                   │
│          ▼                                                          │
│   ┌─────────────┐                                                   │
│   │ 3. ENRICH   │  Gather more context (user info, past behavior)  │
│   └──────┬──────┘                                                   │
│          ▼                                                          │
│   ┌─────────────┐                                                   │
│   │ 4. SCOPE    │  Is this affecting more systems/users?           │
│   └──────┬──────┘                                                   │
│          ▼                                                          │
│   ┌─────────────┐                                                   │
│   │ 5. DECIDE   │  Escalate? Close? Investigate further?           │
│   └──────┬──────┘                                                   │
│          ▼                                                          │
│   ┌─────────────┐                                                   │
│   │ 6. DOCUMENT │  Record findings, actions taken                  │
│   └─────────────┘                                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```


### Real-World Example:
Alert: Multiple failed logins detected for user john.doe

```
┌────────────────────────────────────────────────────────────────────┐
│ STEP 1: RECEIVE                                                    │
├────────────────────────────────────────────────────────────────────┤
│ Alert: 15 failed logins for john.doe in 2 minutes                 │
│ Source IP: 45.33.32.156                                           │
│ Time: 2024-03-15 08:30:00 UTC                                     │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 2: VALIDATE                                                   │
├────────────────────────────────────────────────────────────────────┤
│ Questions to ask:                                                  │
│ - Is john.doe a real user? → YES, Sales team                      │
│ - Is this normal behavior? → NO, usually logs in once             │
│ - Is source IP internal/external? → EXTERNAL                      │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 3: ENRICH                                                     │
├────────────────────────────────────────────────────────────────────┤
│ Check the source IP:                                               │
│ - VirusTotal: Flagged by 8 vendors as malicious                   │
│ - AbuseIPDB: Reported 47 times for brute force                    │
│ - GeoIP: Located in Russia                                        │
│                                                                    │
│ Check the user:                                                    │
│ - Last legitimate login: Yesterday from NYC office                │
│ - VPN user? NO                                                    │
│ - Password recently changed? NO                                   │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 4: SCOPE                                                      │
├────────────────────────────────────────────────────────────────────┤
│ Search: Are other users being targeted by this IP?                │
│                                                                    │
│ Query: index=auth src_ip="45.33.32.156" action=failure            │
│ Result: 5 other users also have failed logins from this IP!       │
│         → This is a password spraying attack                      │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 5: DECIDE                                                     │
├────────────────────────────────────────────────────────────────────┤
│ Verdict: TRUE POSITIVE - Password Spraying Attack                 │
│                                                                    │
│ Actions:                                                           │
│ ✓ Block IP at firewall                                            │
│ ✓ Check if any login succeeded (DATA BREACH?)                     │
│ ✓ Force password reset for targeted users                         │
│ ✓ Escalate to L2/Incident Response                                │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 6: DOCUMENT                                                   │
├────────────────────────────────────────────────────────────────────┤
│ Ticket #12345                                                      │
│ Summary: Password spraying attack from 45.33.32.156               │
│ Affected: 6 users (john.doe, jane.smith, etc.)                    │
│ Actions: IP blocked, passwords reset, escalated to IR             │
│ MITRE: T1110.003 (Password Spraying)                              │
│ Status: Escalated                                                  │
└────────────────────────────────────────────────────────────────────┘
```