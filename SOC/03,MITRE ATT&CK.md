```
┌─────────────────────────────────────────────────────────────────┐
│  MITRE ATT&CK = Your "Cheat Sheet" for Understanding Attackers │
│                                                                 │
│  Think of it as a comprehensive catalog of:                    │
│  • HOW attackers break in                                       │
│  • WHAT they do once inside                                     │
│  • WHICH tools they use                                         │
└─────────────────────────────────────────────────────────────────┘
```

# MITRE ATT&CK
```
ATT&CK = Adversarial Tactics, Techniques, and Common Knowledge

┌──────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK                              │
│                                                              │
│  A globally-accessible knowledge base of adversary          │
│  behaviors based on REAL-WORLD observations                 │
│                                                              │
│  Created by: MITRE Corporation (Non-profit)                 │
│  Website: attack.mitre.org                                  │
│  First Released: 2013                                       │
└──────────────────────────────────────────────────────────────┘
```


**Example:**
```
Think of MITRE ATT&CK like a "Criminal Playbook"

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Just like police study criminal methods to catch them,    │
│  SOC analysts study attacker techniques to detect them     │
│                                                             │
│  Bank Robbery Playbook:          Cyber Attack Playbook:    │
│  ├── Case the bank               ├── Reconnaissance        │
│  ├── Disable alarms              ├── Defense Evasion       │
│  ├── Break into vault            ├── Credential Access     │
│  └── Escape with money           └── Exfiltration          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌────────────────────────────────────────────────────────────────┐
│                   5 Key Benefits for SOC                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. COMMON LANGUAGE                                            │
│     ├── Everyone speaks the same "security language"          │
│     ├── "T1059.001" means the same thing globally             │
│     └── Easy communication with other teams/vendors           │
│                                                                │
│  2. UNDERSTAND ATTACKER MINDSET                                │
│     ├── Know what attackers do after initial access           │
│     ├── Predict next steps in an attack                       │
│     └── Better threat hunting                                  │
│                                                                │
│  3. IMPROVE ALERT ANALYSIS                                     │
│     ├── Quickly categorize alerts                              │
│     ├── Understand severity and context                        │
│     └── Prioritize investigation                               │
│                                                                │
│  4. GAP ANALYSIS                                               │
│     ├── Identify what you CAN detect                           │
│     ├── Identify what you CANNOT detect                        │
│     └── Improve security coverage                              │
│                                                                │
│  5. BETTER REPORTING                                           │
│     ├── Professional incident reports                          │
│     ├── Map attacks to known techniques                        │
│     └── Management understands the threat                      │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```


### The ATT&CK Matrix Layout
```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        MITRE ATT&CK ENTERPRISE MATRIX                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TACTICS (Columns) = WHY - The attacker's goal                              │
│  ─────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐    │
│  │ Initial │Resource │ Execu-  │ Persis- │Privilege│ Defense │Credential│   │
│  │ Access  │Develop. │  tion   │ tence   │  Escal. │ Evasion │ Access  │    │
│  ├─────────┼─────────┼─────────┼─────────┼─────────┼─────────┼─────────┤    │
│  │ T1566   │ T1583   │ T1059   │ T1547   │ T1548   │ T1070   │ T1003   │    │
│  │Phishing │Acquire  │Command  │Boot/    │Abuse    │Indicator│OS Cred  │    │
│  │         │Infra    │ Line    │Logon    │Elevation│Removal  │Dumping  │    │
│  ├─────────┼─────────┼─────────┼─────────┼─────────┼─────────┼─────────┤    │
│  │ T1190   │ T1584   │ T1204   │ T1053   │ T1134   │ T1562   │ T1555   │    │
│  │Exploit  │Compromi-│  User   │Scheduled│ Access  │ Impair  │Creds    │    │
│  │Public   │se Infra │Execution│ Task    │ Token   │Defenses │from PWD │    │
│  │ App     │         │         │         │  Manip  │         │Stores   │    │
│  ├─────────┼─────────┼─────────┼─────────┼─────────┼─────────┼─────────┤    │
│  │  ...    │   ...   │   ...   │   ...   │   ...   │   ...   │   ...   │    │
│  └─────────┴─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘    │
│       ▲                   ▲                                                  │
│       │                   │                                                  │
│  TECHNIQUES (Rows) = HOW - The method used                                  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### ATT&CK HIERARCHY

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATT&CK HIERARCHY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  TACTIC (14 total)                                              │
│  └── The attacker's GOAL                                        │
│      Example: "Execution" - Run malicious code                  │
│                                                                 │
│      ▼                                                          │
│                                                                 │
│  TECHNIQUE (200+ total)                                         │
│  └── HOW they achieve the goal                                  │
│      Example: T1059 "Command and Scripting Interpreter"         │
│                                                                 │
│      ▼                                                          │
│                                                                 │
│  SUB-TECHNIQUE (400+ total)                                     │
│  └── SPECIFIC method within a technique                         │
│      Example: T1059.001 "PowerShell"                            │
│              T1059.003 "Windows Command Shell"                  │
│              T1059.005 "Visual Basic"                           │
│                                                                 │
│      ▼                                                          │
│                                                                 │
│  PROCEDURE                                                      │
│  └── EXACT implementation by a threat actor                     │
│      Example: "APT29 uses encoded PowerShell with -enc flag"    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Technique ID Format Explained
```
┌─────────────────────────────────────────────────────────────────┐
│                   TECHNIQUE ID BREAKDOWN                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│              T1059.001                                          │
│              ─┬───┬──┬─                                         │
│               │   │  │                                          │
│               │   │  └── Sub-technique number (001 = PowerShell)│
│               │   │                                             │
│               │   └───── Technique number (059 = Command Line)  │
│               │                                                 │
│               └───────── T = Technique                          │
│                                                                 │
│  Common Examples You'll See:                                    │
│  ──────────────────────────                                     │
│  T1566.001 = Phishing: Spearphishing Attachment                │
│  T1566.002 = Phishing: Spearphishing Link                      │
│  T1003.001 = OS Credential Dumping: LSASS Memory               │
│  T1053.005 = Scheduled Task/Job: Scheduled Task                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```