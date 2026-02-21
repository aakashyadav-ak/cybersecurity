
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