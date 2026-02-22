## 1: EDR vs XDR

###  EDR = Endpoint Detection & Response
FOCUS: Endpoints only (laptops, desktops, servers)

**CAPABILITIES:**
- Process monitoring
- File activity
- Registry changes
- Network connections from endpoint
- Threat detection
- Host isolation
- Forensic investigation

**EXAMPLES:**
- CrowdStrike Falcon
- Microsoft Defender for Endpoint
- SentinelOne
- Carbon Black


### XDR = Extended Detection & Response
**FOCUS:** Multiple sources (endpoints + network + cloud + email)

**CAPABILITIES:**
- Everything EDR does
- Network traffic analysis
- Email security
- Cloud workload protection
- Identity monitoring
- Cross-source correlation

**EXAMPLES:**
- Microsoft 365 Defender
- Palo Alto Cortex XDR
- CrowdStrike Falcon Complete
- Trend Micro Vision One


#### EDR vs XDR Comparison

| Aspect          | EDR                          | XDR                                                                 |
|-----------------|------------------------------|----------------------------------------------------------------------|
| Scope           | Endpoints only               | Endpoints + Network + Cloud + Email                                 |
| Data Sources    | Single (endpoint)            | Multiple                                                             |
| Correlation     | Within endpoint              | Across all sources                                                   |
| Visibility      | Host-level                   | Enterprise-wide                                                      |
| Example Alert   | "Malware on LAPTOP-05"       | "Phishing email → User clicked → Malware on LAPTOP-05 → Lateral movement to SERVER-01" |


_____

# 2: Process Tree Analysis

## Process Tree
 Shows parent-child relationships between processes.

**NORMAL PROCESS TREE:**

explorer.exe (User desktop)
    └── chrome.exe (User opened browser)
        └── chrome.exe (Browser tabs)

**SUSPICIOUS PROCESS TREE: 🚨**

WINWORD.EXE (User opened Word doc)
    └── cmd.exe (Command prompt spawned!)
        └── powershell.exe (PowerShell executed!)
            └── whoami.exe (Reconnaissance!)


#### Suspicious Parent-Child Relationships

## Suspicious Parent-Child Process Relationships (Windows)

| Parent Process            | Suspicious Child           | Indicates         |
| ------------------------- | -------------------------- | ----------------- |
| WINWORD.EXE               | cmd.exe, powershell.exe    | Macro malware     |
| EXCEL.EXE                 | cmd.exe, powershell.exe    | Macro malware     |
| OUTLOOK.EXE               | cmd.exe, powershell.exe    | Email exploit     |
| iexplore.exe / chrome.exe | cmd.exe, powershell.exe    | Drive-by download |
| svchost.exe               | cmd.exe (not normal child) | Process injection |
| wmiprvse.exe              | powershell.exe             | WMI abuse         |
| mshta.exe                 | powershell.exe, cmd.exe    | HTA attack        |

#### Normal vs 🚨 Suspicious
```
✅ NORMAL:
explorer.exe → notepad.exe (User opened Notepad)
services.exe → svchost.exe (Windows service starting)
cmd.exe → ping.exe (Admin running ping)

🚨 SUSPICIOUS:
WINWORD.EXE → powershell.exe (Macro execution!)
OUTLOOK.EXE → mshta.exe (Email exploit!)
svchost.exe → whoami.exe (Reconnaissance!)
explorer.exe → certutil.exe -urlcache (Download!)
```


____

# 3: Suspicious File Paths

