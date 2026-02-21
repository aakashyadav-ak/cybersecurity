
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