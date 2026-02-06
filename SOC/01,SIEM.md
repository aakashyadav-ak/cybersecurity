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