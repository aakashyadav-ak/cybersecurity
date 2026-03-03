**Splunk Enterprise is a SIEM & log analysis platform used to:**
- Collect logs
- Search logs
- Analyze events
- Create dashboards
- Detect threats
- Generate alerts

**SOC analysts use Splunk daily to:**
- Investigate alerts
- Hunt threats
- Monitor suspicious activity
- Create detection rules

#### Endpoint → Forwarder → Indexer → Search Head → SOC Analyst


```
Data Sources          Forwarder         Indexer          Search Head
───────────          ─────────         ───────          ───────────

Firewall ──┐
            ├──→  Universal   ──→  ┌──────────┐    ┌──────────────┐
Windows ───┤      Forwarder       │ INPUT     │    │              │
            │                      │    ↓      │    │  SPL Query   │
Linux ─────┤                      │ PARSING   │    │  Dashboard   │
            │      Heavy          │    ↓      │    │  Alerts      │
IDS/IPS ───┤      Forwarder ──→  │ INDEXING  │←──│  Reports     │
            │                      │    ↓      │    │              │
Cloud ─────┘      Syslog ────→   │ SEARCHING │    └──────────────┘
                                   └──────────┘
```
# Splunk Architecture

## Core Components:

### 1) Forwarder
- Installed on endpoints (Windows/Linux servers)
- Collects logs
- Sends logs to Indexer

**Types:**
- Universal Forwarder (lightweight)
- Heavy Forwarder (can parse/filter logs)

### 2) Indexer
- Receives logs
- Parses logs
- Stores logs in indexes
- Makes data searchable

**Think of it as:**
 Storage + Processing Engine

### 3) Search Head
- Where users log in
- Run searches (SPL)
- Create dashboards
- Create alerts



____

## Index
An Index is where logs are stored.

**Examples:**
- index=windows
- index=firewall
- index=proxy
- index=linux

**SOC analysts always start search with:**
```
index=windows
```

____


## Splunk Data Structure

**Every event has:**
- `_time` → timestamp
- host → system name
- source → log file path
- sourcetype → log type
- index → storage location

**Example:**
```
index=windows sourcetype=WinEventLog:Security
```


____


## SPL (Search Processing Language)

SPL is how you search logs.

#### Basic Search
```
index=windows
```
Search all Windows logs.

#### Keyword Search
```
index=windows "failed"
```


#### Field Based Search
```
index=windows EventCode=4625
```

4625 = Failed login

#### stats

Used to aggregate data.

**Example:**
```
index=windows EventCode=4625
| stats count by user

```
Shows failed login count per user.

#### top
```
index=windows EventCode=4625
| top user
```


#### table
```
index=windows EventCode=4688
| table _time host user process_name
```

#### sort
```
index=windows EventCode=4688
| sort - count
```


#### where
```
index=windows EventCode=4688
| where count > 10
```



_____

## Creating Alerts

**Example:** Alert for brute force

```
index=windows EventCode=4625
| stats count by user
| where count > 20
```

Save As → Alert
Trigger → If results > 0

__________


## Dashboards in Splunk
Dashboards are visual panels (charts, tables, graphs).

**Used in SOC to monitor:**
- Failed logins
- Top talkers
- Malware alerts
- Firewall denies

### How to Create Dashboard

1. Run query
2. Click Visualization
3. Choose chart type (bar, pie, line)
4. Save As → Dashboard panel


**Example:**
```
index=windows EventCode=4625
| stats count by host
```
Visualize as bar chart.

____



## Splunk Apps 
#### 1) Splunk Enterprise Security

- SIEM layer
- Correlation searches
- Risk scoring
- Incident review
Used in enterprise SOC.

#### 2) Splunk SOAR

- Automation
- Playbooks
- Auto response