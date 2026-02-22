#  1: Critical Windows Event IDs

| Event ID | What It Means                   | Category             |
| -------- | ------------------------------- | -------------------- |
| 4624     | Successful Logon                | Authentication       |
| 4625     | Failed Logon                    | Authentication       |
| 4688     | Process Created                 | Execution            |
| 4720     | User Account Created            | Account Changes      |
| 4732     | User Added to Admin Group       | Privilege Escalation |
| 4769     | Kerberos Service Ticket         | Lateral Movement     |
| 7045     | Service Installed               | Persistence          |
| 1102     | Log Cleared                     | Defense Evasion      |
| 4104     | PowerShell Script Block Logging | Execution            |

###  Authentication Events

**4624 - Successful Logon**
```
✅ User logged in successfully
✅ CHECK: Logon Type field

LOGON TYPES (Memorize!):
┌──────┬─────────────────┬──────────────────────┐
│ Type │ Name            │ Meaning              │
├──────┼─────────────────┼──────────────────────┤
│  2   │ Interactive     │ Physical login       │
│  3   │ Network         │ SMB, network share   │
│  4   │ Batch           │ Scheduled task       │
│  5   │ Service         │ Service startup      │
│  7   │ Unlock          │ Workstation unlock   │
│ 10   │ RemoteInteractive│ RDP login           │
└──────┴─────────────────┴──────────────────────┘

🚨 SUSPICIOUS:
- Type 10 (RDP) at 3 AM
- Type 3 from unknown IP
- Type 2 on server (who's physically there?)
```

**4625 - Failed Logon**
```
❌ Login attempt failed
✅ CHECK: Failure Reason, Source IP, Account Name

FAILURE CODES:
┌─────────┬────────────────────────┐
│ Code    │ Meaning                │
├─────────┼────────────────────────┤
│ 0xC000006A │ Wrong password      │
│ 0xC000006D │ Wrong username      │
│ 0xC0000072 │ Account disabled    │
│ 0xC0000234 │ Account locked      │
└─────────┴────────────────────────┘

🚨 ALERT PATTERN:
- Multiple 4625 from same IP = Brute Force
- Multiple 4625 on different accounts = Password Spray
- 4625 followed by 4624 = Successful attack!
```



## Process & Execution Events

**4688 - Process Creation**
```
✅ New process started
✅ CRITICAL: Shows command line (if enabled)

KEY FIELDS:
- New Process Name: What ran
- Creator Process: What spawned it (parent)
- Command Line: Full command with arguments

🚨 SUSPICIOUS EXAMPLES:
- powershell.exe spawned by WINWORD.EXE (Macro!)
- cmd.exe spawned by outlook.exe (Phishing!)
- certutil.exe with -urlcache (Download!)
```

**4104 - PowerShell Script Block**
```
✅ PowerShell code executed
✅ Shows ACTUAL script content (decoded!)

🚨 LOOK FOR:
- DownloadString
- IEX (Invoke-Expression)
- -enc or -encoded
- Invoke-Mimikatz
- New-Object Net.WebClient
```


## Account Events

**4720 - User Account Created**
```
✅ New user account made

🚨 SUSPICIOUS:
- Created at odd hours
- Created by non-admin
- Name mimics system (admin1, svc_backup)
- Immediately added to admin group
```

**4732 - User Added to Privileged Group**
```
✅ Someone added to local Administrators group

🚨 ALWAYS INVESTIGATE:
- Who added?
- Who was added?
- When? (after hours = suspicious)
- Expected change? (check with IT)
```

## Kerberos Event

**4769 - Kerberos Service Ticket (TGS)**
```
✅ Service ticket requested

🚨 KERBEROASTING DETECTION:
- Many 4769 events
- From same user
- Requesting tickets for multiple services
- Encryption type: 0x17 (RC4) = weak, targeted!
```


## Persistence Event

**7045 - Service Installed**
```
✅ New Windows service created

🚨 SUSPICIOUS:
- Service from Temp folder
- Service with random name
- Service running as SYSTEM
- Service pointing to script/PowerShell
```


## Anti-Forensics Event

**1102 - Audit Log Cleared**
```
✅ Someone cleared Windows Event Logs

🚨 ALWAYS P1 ALERT!
- Attackers clear logs to hide activity
- Check: Who cleared? When?
- Immediately investigate what happened BEFORE clearing
```


### short summary
```
AUTHENTICATION:
4624 = Success ✅
4625 = Failed ❌

EXECUTION:
4688 = Process started
4104 = PowerShell ran

ACCOUNT CHANGES:
4720 = User created
4732 = Added to admin group

LATERAL MOVEMENT:
4769 = Kerberos ticket (Kerberoasting)

PERSISTENCE:
7045 = Service installed

ANTI-FORENSICS:
1102 = Logs cleared 🚨
```

____


#  2: Detection Patterns