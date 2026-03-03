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