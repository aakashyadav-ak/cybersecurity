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
