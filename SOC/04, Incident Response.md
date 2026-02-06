
#  Incident Response
Incident Response (IR) = The process of detecting, investigating, and recovering from security incidents (attacks, breaches, malware)

```
Fire Department          vs          Incident Response
─────────────────────────────────────────────────────
Detect fire (alarm)      →          Detect attack (EDR alert)
Respond to location      →          Investigate affected systems
Contain fire (stop spread) →        Contain attack (isolate host)
Extinguish fire          →          Remove malware/attacker
Investigate cause        →          Root cause analysis
Prevent future fires     →          Improve defenses
```

## Security Incident
Incident = Any event that threatens the confidentiality, integrity, or availability of systems/data.


## Event vs Alert vs Incident
```
┌─────────────────────────────────────────────────────────┐
│                      ALL EVENTS                         │
│  (Millions of logs: logins, file access, network, etc.) │
│                                                         │
│    ┌─────────────────────────────────────────────┐      │
│    │              SECURITY EVENTS                │      │
│    │  (Subset that might be security-related)    │      │
│    │                                             │      │
│    │    ┌─────────────────────────────────┐      │      │
│    │    │           ALERTS                │      │      │
│    │    │  (Events flagged by SIEM/EDR)   │      │      │
│    │    │                                 │      │      │
│    │    │    ┌───────────────────┐        │      │      │
│    │    │    │    INCIDENTS      │        │      │      │
│    │    │    │ (Confirmed threats│        │      │      │
│    │    │    │  requiring action)│        │      │      │
│    │    │    └───────────────────┘        │      │      │
│    │    └─────────────────────────────────┘      │      │
│    └─────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────┘

Example:
- Event: User john.doe logged in at 9:00 AM
- Security Event: User john.doe logged in from new country
- Alert: EDR flagged "Impossible travel detected"
- Incident: Confirmed - john.doe's account was compromised
```

### Goals of Incident Response
```
1. MINIMIZE DAMAGE
   └─ Stop attacker before they steal data/encrypt files

2. REDUCE RECOVERY TIME
   └─ Get business back to normal ASAP

3. PRESERVE EVIDENCE
   └─ Collect proof for investigation/legal action

4. PREVENT RECURRENCE
   └─ Fix the vulnerability that allowed the attack

5. LEARN & IMPROVE
   └─ Update defenses based on lessons learned
```


---
#  IR Lifecycle (NIST vs SANS Frameworks)