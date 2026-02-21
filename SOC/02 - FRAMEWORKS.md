
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