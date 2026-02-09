
## 2.1 Footprinting Concepts

### What is Footprinting?
Footprinting is the first step in ethical hacking where the attacker gathers information about a target system. It is the process of collecting as much information as possible about a target network, system, or organization.

### Footprinting Process Flow
```
┌─────────────────────────────────────────────────────────────────┐
│ FOOTPRINTING PROCESS │
├─────────────────────────────────────────────────────────────────┤
│ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ TARGET │───▶│ PASSIVE │───▶│ ACTIVE │───▶│ REPORT │ │
│ │SELECTION │ │FOOTPRINT │ │FOOTPRINT │ │ FINDINGS │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│ │
│ Identify No direct Direct Document │
│ target contact interaction all info │
│ │
└─────────────────────────────────────────────────────────────────┘
```


### Objectives of Footprinting
```
┌─────────────────────────────────────────────────────────────────┐
│ FOOTPRINTING OBJECTIVES │
├─────────────────────────────────────────────────────────────────┤
│ │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ 1. Know Security Posture │ │
│ │ └── Understand target's security measures │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ 2. Reduce Focus Area │ │
│ │ └── Narrow down IP ranges, networks, domain names │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ 3. Identify Vulnerabilities │ │
│ │ └── Find weak points in target's security │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ 4. Draw Network Map │ │
│ │ └── Create visual representation of network │ │
│ └─────────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────┘
```


### Information Gathered During Footprinting

| Category | Information |
|----------|-------------|
| **Organization** | Employee details, addresses, phone numbers, branches |
| **Network** | Domain names, IP addresses, network topology |
| **Systems** | Operating systems, web servers, applications |
| **Technical** | Email headers, DNS records, firewall rules |

---

## 2.2 Types of Footprinting

### Passive vs Active Footprinting
