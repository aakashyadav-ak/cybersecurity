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
