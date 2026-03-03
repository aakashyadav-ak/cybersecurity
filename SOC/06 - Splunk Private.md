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

# Splunk Architecture

## Core Components:

### 1) Forwarder
- Installed on endpoints (Windows/Linux servers)
- Collects logs
- Sends logs to Indexer

**Types:**
- Universal Forwarder (lightweight)
- Heavy Forwarder (can parse/filter logs)
