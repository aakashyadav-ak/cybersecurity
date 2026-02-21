
#  1: MITRE ATT&CK Framework (Tactic vs Technique)

- MITRE ATT&CK is THE industry standard framework for understanding adversary behavior.

- MITRE Corporation created the ATT&CK framework.


#### **ATT&CK** = Adversarial Tactics, Techniques, and Common Knowledge

It's a giant encyclopedia of how hackers attack systems, based on real-world observations.

It is a knowledge base of:
- How attackers behave
- Real-world attack techniques
- Mapped attack patterns

#### Why SOC Analysts Use MITRE?

- To classify attacks
- To understand attacker behavior
- To map alerts to known techniques
- To improve detection coverage


## ATT&CK Structure: Tactics → Techniques → Sub-Techniques

```
┌─────────────────────────────────────────────┐
│  TACTICS (The "WHY")                        │
│  "What is the attacker's goal?"             │
│                                             │
│  ↓                                          │
│                                             │
│  TECHNIQUES (The "WHAT")                    │
│  "What method are they using?"              │
│                                             │
│  ↓                                          │
│                                             │
│  SUB-TECHNIQUES (The "HOW")                 │
│  "Specific variation of the technique"      │
└─────────────────────────────────────────────┘
```

###  TACTICS - The "WHY"
**Tactics** = The adversary's objective at each stage of the attack.

##### The 14 Tactics (in attack order):

| # | Tactic | Simple Explanation | Attacker's Goal |
| :--- | :--- | :--- | :--- |
| 1 | **Reconnaissance** | Gathering information | "Let me research my target" |
| 2 | **Resource Development** | Preparing attack infrastructure | "Let me buy a domain, setup server" |
| 3 | **Initial Access** | Getting into the network | "How do I get in?" |
| 4 | **Execution** | Running malicious code | "Let me run my malware" |
| 5 | **Persistence** | Maintaining access | "How do I stay in even after reboot?" |
| 6 | **Privilege Escalation** | Getting higher permissions | "I need admin rights" |
| 7 | **Defense Evasion** | Avoiding detection | "How do I hide from security tools?" |
| 8 | **Credential Access** | Stealing passwords/tokens | "I need more credentials" |
| 9 | **Discovery** | Learning about the environment | "What systems exist? Who are the admins?" |
| 10 | **Lateral Movement** | Moving to other systems | "Let me access other computers" |
| 11 | **Collection** | Gathering data to steal | "Where's the valuable data?" |
| 12 | **Command and Control (C2)** | Communicating with attacker's server | "Let me phone home for instructions" |
| 13 | **Exfiltration** | Stealing data out | "Time to upload the data" |
| 14 | **Impact** | Causing damage | "Let me encrypt/delete everything" |


**Example:**
```
Attacker's Journey:

1. RECONNAISSANCE → Research company employees on LinkedIn
2. INITIAL ACCESS → Send phishing email to employee
3. EXECUTION → Employee clicks link, malware runs
4. PERSISTENCE → Malware creates scheduled task
5. PRIVILEGE ESCALATION → Exploit vulnerability to get admin rights
6. CREDENTIAL ACCESS → Dump passwords from memory
7. LATERAL MOVEMENT → Use stolen credentials to access server
8. COLLECTION → Find database with customer data
9. C2 → Download additional tools from attacker server
10. EXFILTRATION → Upload database to attacker's cloud
11. IMPACT → Deploy ransomware to cover tracks
```

Each step = A different TACTIC

### TECHNIQUES - The "WHAT"
Techniques = Specific methods used to achieve a tactic.

One tactic can have MANY techniques.

#### Example: Initial Access Tactic
**Tactic Goal:** Get into the network

**Different Techniques to achieve this:**

| Technique ID | Technique Name                         | How it Works                     |
|-------------|----------------------------------------|----------------------------------|
| T1566      | Phishing                                | Send malicious email             |
| T1190      | Exploit Public-Facing Application       | Hack vulnerable web server       |
| T1133      | External Remote Services                | Brute force VPN login            |
| T1078      | Valid Accounts                          | Use stolen credentials           |
| T1091      | Replication Through Removable Media     | USB drive with malware           |

Same goal (Initial Access), but 5+ different methods!

## SUB-TECHNIQUES - The "HOW" (Variations)
Sub-Techniques = Specific variations of a technique.

#### Example: Phishing (T1566)
**Main Technique:** Phishing

Sub-Techniques (different types of phishing):

| Sub-Technique ID | Name                         | Description                                      |
|------------------|------------------------------|--------------------------------------------------|
| T1566.001        | Spearphishing Attachment     | Email with malicious file (e.g., invoice.exe)    |
| T1566.002        | Spearphishing Link           | Email with malicious link                        |
| T1566.003        | Spearphishing via Service    | Phishing via LinkedIn, Teams, etc.               |
| T1566.004        | Spearphishing Voice          | Vishing (voice phishing)                         |



### Tactic vs Technique vs Sub-Technique (Visual)
```
TACTIC: Initial Access
   ↓
   TECHNIQUE: T1566 - Phishing
      ↓
      SUB-TECHNIQUE: T1566.001 - Spearphishing Attachment
         ↓
         PROCEDURE: Attacker sends "Invoice.pdf.exe" to victim
```




## How SOC Analysts Use ATT&CK


### 1. Alert Mapping
When you see an alert, map it to ATT&CK:
```
Alert: "Suspicious PowerShell execution detected"

Map to ATT&CK:
- TACTIC: Execution
- TECHNIQUE: T1059 - Command and Scripting Interpreter
- SUB-TECHNIQUE: T1059.001 - PowerShell
```

### 2. Threat Hunting
Search for specific TTPs in your environment:
```
"Let me hunt for Credential Dumping (T1003) 
in our environment to see if attackers are 
stealing passwords"
```


### 3. Incident Investigation
Map the full attack chain:
```
Incident: Ransomware Attack

ATT&CK Mapping:
1. Initial Access: T1566.001 (Phishing email)
2. Execution: T1204.002 (User opened attachment)
3. Persistence: T1053.005 (Scheduled task created)
4. Credential Access: T1003.001 (LSASS memory dump)
5. Lateral Movement: T1021.001 (RDP to other systems)
6. Impact: T1486 (Data encrypted for ransom)
```

### 4. Detection Engineering
Create detection rules based on techniques:
```
"We need detection for T1003 (Credential Dumping)
Let's create a SIEM rule that alerts when:
- lsass.exe is accessed by unusual processes
- Mimikatz command line patterns detected
- Windows Event ID 4656 (LSASS access)
```


____

# 2: Mapping 4 Common Attacks to MITRE ATT&CK

## The 4 Must-Know Techniques

1. T1110 - Brute Force
2. T1566 - Phishing  
3. T1059.001 - PowerShell
4. T1003 - Credential Dumping

### 1) BRUTE FORCE → T1110
Attackers try many passwords until they find the correct one

- Technique ID: T1110
- Technique Name: Brute Force
- Tactic: Credential Access (TA0006)

#### examples
 - 1: SSH Brute Force
 - 2: Password Spraying

#### How to Detect T1110:
- **Detection Methods:**
- Multiple failed login attempts
- Account lockouts
- Unusual login patterns
- SIEM Rules:
```
IF failed_logins > 20 within 10 minutes
FROM same source_ip
THEN ALERT "Possible Brute Force (T1110)"
```



#### SOC Response to T1110:
**When you see brute force alert:**

1. ✅ Identify the target (Which account/system?)
2. ✅ Check if successful (Any successful logins mixed in?)
3. ✅ Block source IP (at firewall)
4. ✅ Lock account (if compromised)
5. ✅ Force password reset (if needed)
6. ✅ Enable MFA (prevent future attempts)


### 2) PHISHING → T1566
- Attackers send deceptive messages to trick users into clicking links, opening files, or revealing credentials.
- Tricking people via email/messages

- Technique ID: T1566
- Technique Name: Phishing
- Tactic: Initial Access (TA0001)


#### How to Detect T1566:
 **SIEM Detection:**
```
 RULE: Email with attachment + external sender + 
      suspicious keywords ("invoice", "urgent", "password")
→ ALERT for review
```


### SOC Response to T1566:
**When phishing email detected:**

- ✅ Quarantine the email (remove from all inboxes)
- ✅ Check who clicked (review proxy/email logs)
- ✅ If clicked - investigate:
	- Did user download file?
	- Did user enter credentials?
	- Scan user's system for malware
- ✅ Block sender domain (email gateway)
- ✅ Block malicious URLs (web proxy)
- ✅ Security awareness (educate users)
- ✅ Submit to threat intel (PhishTank, etc.)



### 3) POWERSHELL → T1059.001
Attackers use PowerShell (Windows built-in tool) to execute malicious commands.

- Technique ID: T1059.001
- Parent Technique: T1059 - Command and Scripting Interpreter
- Sub-Technique: PowerShell
- Tactic: Execution (TA0002)

Why Powershell
- Pre-installed on Windows (no need to upload tools)
- Powerful capabilities (access to .NET, WMI, registry)
- Often whitelisted (security tools trust it)
- Can run in memory (fileless attacks)
- Easy to obfuscate (encode/encrypt commands)



#### How to Detect T1059.001:
**Detection Methods:**
1. PowerShell Logging (Enable These!):
```
Windows Event IDs:
- 4103: Module logging
- 4104: Script block logging (captures full commands!)
- 4105: Script block logging start
- 4106: Script block logging stop
```

2. SIEM Rules:
```
2. RULE: PowerShell executed with:
  - Encoded commands (-enc)
  - AND Network activity (DownloadString)
  - AND Hidden window (-w hidden)
  
→ ALERT: Suspicious PowerShell (T1059.001)
```

#### SOC Response to T1059.001:
When suspicious PowerShell detected:

- ✅ Capture the command (from Event ID 4104)
- ✅ Decode if obfuscated (use CyberChef, PowerShell decoder)
- ✅ Analyze what it does:
	- Downloads file? → Get URL, analyze
	- Connects to IP? → Check IP reputation
	- Accesses LSASS? → Credential theft!
- ✅ Check parent process (what launched PowerShell?)
	- Word.exe → Macro attack
	- cmd.exe → Possible script
- ✅ Isolate system (if malicious)
- ✅ Hunt for similar activity (other systems affected?)



###  CREDENTIAL DUMPING → T1003
Attackers steal passwords/hashes from operating system memory, files, or databases.

- Technique ID: T1003
- Technique Name: OS Credential Dumping
- Tactic: Credential Access (TA0006)

**example:**
**Mimikatz LSASS Dump (T1003.001)**
```
ATTACK FLOW:
1. Attacker gains admin rights on workstation
2. Runs Mimikatz (credential dumping tool)
3. Command: sekurlsa::logonpasswords

Output:
Authentication Id : 0 ; 123456
Session           : Interactive from 1
User Name         : john.doe
Domain            : COMPANY
SID               : S-1-5-21-...
        msv :
         [00000003] Primary
         * Username : john.doe
         * Domain   : COMPANY
         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
         * SHA1     : a3d5c...

4. Attacker now has:
   - Plaintext password (if available)
   - NTLM hash (can be used for Pass-the-Hash)

5. Uses stolen credentials to access other systems

ATT&CK Mapping:
- TACTIC: Credential Access
- TECHNIQUE: T1003 - OS Credential Dumping
- SUB-TECHNIQUE: T1003.001 - LSASS Memory
```

#### How to Detect T1003:

1. Process Monitoring:
```
⚠️ Suspicious processes accessing LSASS:
   - mimikatz.exe
   - procdump.exe (targeting lsass)
   - taskmgr.exe creating lsass dump
   - Non-system processes reading lsass.exe memory

Windows Event ID: 4656 (Object access)
- Object Name: lsass.exe
- Process Name: [suspicious tool]
```

2. SIEM Rules:
```
RULE 1: LSASS Memory Access
IF process_name != (wininit.exe, csrss.exe, svchost.exe)
AND target_process == "lsass.exe"
AND access_rights == PROCESS_VM_READ
THEN ALERT "Credential Dumping Attempt (T1003.001)"

RULE 2: Known Tool Detection
IF process_name in (mimikatz.exe, procdump.exe, pwdump.exe)
THEN ALERT "Credential Dumping Tool (T1003)"
```


#### SOC Response to T1003:

**When credential dumping detected:**
- ✅ ISOLATE affected system immediately
- ✅ Assume credentials compromised:
	- Force password reset for all users who logged into that system
	- Revoke all active sessions
	- Reset service account passwords
- ✅ Check for lateral movement:
	- Did attacker use stolen creds elsewhere?
	- Search for logins from affected accounts
- ✅ Hunt for persistence:
	- New user accounts created?
	- Scheduled tasks?
	- Backdoors?
- ✅ Forensic preservation:
	- Capture memory image
	- Preserve logs
	- Document timeline
- ✅ Escalate to Incident Response team


### Summary of 4 Key Techniques

| Technique | ID | Tactic | What Happens | Detection | Response |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Brute Force** | T1110 | Credential Access | Trying many passwords | Multiple failed logins | Block IP, lock account |
| **Phishing** | T1566 | Initial Access | Tricking user via email | Email gateway, user reports | Quarantine email, block domain |
| **PowerShell** | T1059.001 | Execution | Running malicious commands | Event 4104, suspicious flags | Decode command, isolate system |
| **Credential Dumping** | T1003 | Credential Access | Stealing passwords from memory | LSASS access, Mimikatz detection | Isolate, reset passwords, hunt |


### must learn
```
T1110 = Brute Force (Credential Access)
  └─ Guessing passwords

T1566 = Phishing (Initial Access)
  └─ Tricking users via messages

T1059.001 = PowerShell (Execution)
  └─ Running malicious commands

T1003 = Credential Dumping (Credential Access)
  └─ Stealing passwords from memory
```