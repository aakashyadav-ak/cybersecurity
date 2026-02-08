# Module 1: Introduction to Ethical Hacking

## 1.1 Information Security Overview

### What is Information Security?
Information Security (InfoSec) refers to the protection of information and information systems from unauthorized access, use, disclosure, disruption, modification, or destruction.

### CIA Triad
The foundation of information security:

```
        Confidentiality
             /\
            /  \
           /    \
          /      \
         /________\
   Integrity    Availability
```

| Principle | Description | Example |
|-----------|-------------|---------|
| **Confidentiality** | Data accessible only to authorized users | Encryption, Access Controls |
| **Integrity** | Data is accurate and unaltered | Hashing, Digital Signatures |
| **Availability** | Data accessible when needed | Backups, Redundancy |

### Additional Security Concepts

| Concept | Description |
|---------|-------------|
| **Authenticity** | Verifying the identity of users |
| **Non-Repudiation** | Ensuring actions cannot be denied |
| **Accountability** | Tracking actions to specific users |

---

## 1.2 Types of Threats and Attack Vectors

### Threat Categories

**Natural Threats**
- Earthquakes
- Floods
- Fires

**Physical Threats**
- Theft
- Vandalism
- Hardware failure

**Human Threats**
- Hackers
- Insiders
- Social engineers

**Technical Threats**
- Malware
- Exploits
- Zero-days

### Attack Vectors

| Vector                            | Description                      |
| --------------------------------- | -------------------------------- |
| Cloud computing threats           | Attacks on cloud infrastructure  |
| Advanced Persistent Threats (APT) | Long-term targeted attacks       |
| Viruses and worms                 | Self-replicating malware         |
| Ransomware                        | Encrypts data for ransom         |
| Mobile threats                    | Attacks on mobile devices        |
| Botnets                           | Network of compromised systems   |
| Insider attacks                   | Threats from within organization |
| Phishing                          | Social engineering via email     |
| Web application threats           | SQL injection, XSS               |
| IoT threats                       | Attacks on IoT devices           |

---

## 1.3 Hacking Concepts

### What is Hacking?
Exploiting system vulnerabilities and compromising security controls to gain unauthorized access to system resources.

### Types of Hackers

| Type | Hat Color | Description |
|------|-----------|-------------|
| **White Hat** | White | Ethical hackers, security professionals |
| **Black Hat** | Black | Malicious hackers, criminals |
| **Gray Hat** | Gray | Work both offensively and defensively |
| **Suicide Hackers** | - | Attack without fear of consequences |
| **Script Kiddies** | - | Unskilled, use existing tools |
| **Cyber Terrorists** | - | Politically motivated attacks |
| **State-Sponsored** | - | Government-backed hackers |
| **Hacktivists** | - | Hack for social/political causes |

### Hacking Phases (5 Phases)

| Phase | Name | Description | Activities |
|-------|------|-------------|------------|
| 1 | **Reconnaissance** | Gathering information | Passive/Active information gathering |
| 2 | **Scanning** | Identifying vulnerabilities | Port scanning, vulnerability scanning |
| 3 | **Gaining Access** | Exploiting vulnerabilities | Password cracking, exploits |
| 4 | **Maintaining Access** | Keeping access | Backdoors, rootkits, trojans |
| 5 | **Clearing Tracks** | Hiding evidence | Log deletion, hiding files |

---

## 1.4 Ethical Hacking Concepts

### What is Ethical Hacking?
Authorized practice of detecting vulnerabilities in systems by bypassing security to identify potential data breaches.

### Purpose of Ethical Hacking
- [ ] Identify vulnerabilities
- [ ] Test security controls
- [ ] Ensure compliance
- [ ] Protect against attacks
- [ ] Improve security posture
- [ ] Safeguard customer data
- [ ] Avoid security breaches

### Skills of an Ethical Hacker

| Technical Skills | Non-Technical Skills |
|-----------------|---------------------|
| Networking knowledge | Problem-solving |
| Operating systems | Communication |
| Programming/Scripting | Persistence |
| Security concepts | Ethics |
| Web technologies | Documentation |
| Database knowledge | Time management |
| Cryptography | Continuous learning |

### Scope and Limitations
**What Ethical Hackers Must Know:**
1. What they can test
2. What they cannot test
3. Timeline of testing
4. Reporting requirements
5. Legal boundaries

---

## 1.5 Cyber Kill Chain

### Lockheed Martin Cyber Kill Chain
A framework describing stages of a cyber attack.

| Stage                        | Description                   | Example                 |
| ---------------------------- | ----------------------------- | ----------------------- |
| **1. Reconnaissance**        | Research and identify targets | Email harvesting, OSINT |
| **2. Weaponization**         | Create malicious payload      | Exploit + backdoor      |
| **3. Delivery**              | Transmit weapon to target     | Email, USB, website     |
| **4. Exploitation**          | Trigger the exploit           | Vulnerability exploited |
| **5. Installation**          | Install malware               | Backdoor installed      |
| **6. Command & Control**     | Remote control channel        | C2 server communication |
| **7. Actions on Objectives** | Achieve goals                 | Data exfiltration       |

### MITRE ATT&CK Framework
Alternative framework with tactics and techniques:

| Tactic | Description |
|--------|-------------|
| Initial Access | How attackers get in |
| Execution | Running malicious code |
| Persistence | Maintaining foothold |
| Privilege Escalation | Getting higher access |
| Defense Evasion | Avoiding detection |
| Credential Access | Stealing credentials |
| Discovery | Learning the environment |
| Lateral Movement | Moving through network |
| Collection | Gathering data |
| Exfiltration | Stealing data |
| Impact | Causing damage |

---

## 1.6 Information Security Controls

### Types of Controls

| Control Type | Description | Examples |
|--------------|-------------|----------|
| **Physical** | Protect physical assets | Guards, locks, CCTV |
| **Technical** | Use technology | Firewalls, encryption, IDS |
| **Administrative** | Policies and procedures | Training, policies |

### Control Functions

| Function | Purpose | Example |
|----------|---------|---------|
| **Preventive** | Stop attacks | Firewall, authentication |
| **Detective** | Identify attacks | IDS, logs, audits |
| **Corrective** | Fix after attack | Patches, backups |
| **Deterrent** | Discourage attacks | Warning banners |
| **Recovery** | Restore operations | Disaster recovery |
| **Compensating** | Alternative controls | When primary fails |

### Defense in Depth
Multiple layers of security:

1. **Policies** - Outermost layer
2. **Physical** - Physical security
3. **Perimeter** - Firewalls, DMZ
4. **Network** - Network segmentation
5. **Host** - Endpoint security
6. **Application** - Application security
7. **Data** - Innermost layer (encryption)

---

## 1.7 Information Security Laws and Standards

### Important Regulations

| Law/Standard | Description | Region |
|--------------|-------------|--------|
| **PCI DSS** | Payment Card Industry Data Security Standard | Global |
| **HIPAA** | Health Insurance Portability and Accountability Act | USA |
| **SOX** | Sarbanes-Oxley Act | USA |
| **GDPR** | General Data Protection Regulation | EU |
| **DMCA** | Digital Millennium Copyright Act | USA |
| **FISMA** | Federal Information Security Management Act | USA |
| **ISO 27001** | Information Security Management System | Global |

### Key Compliance Frameworks
- NIST Cybersecurity Framework
- ISO 27001/27002
- COBIT
- CIS Controls
- SOC 2

---

## 1.8 Penetration Testing Concepts

### Types of Penetration Testing

| Type | Knowledge Level | Also Known As |
|------|-----------------|---------------|
| **Black Box** | No knowledge | Zero-knowledge testing |
| **White Box** | Full knowledge | Full-disclosure testing |
| **Gray Box** | Partial knowledge | Partial-knowledge testing |

### Penetration Testing Phases

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Pre-engagement | Scope, rules, authorization |
| 2 | Reconnaissance | Information gathering |
| 3 | Scanning | Identify vulnerabilities |
| 4 | Exploitation | Exploit vulnerabilities |
| 5 | Post-Exploitation | Maintain access, pivot |
| 6 | Reporting | Document findings |

### Important Documents

| Document | Purpose |
|----------|---------|
| **NDA** | Non-Disclosure Agreement |
| **ROE** | Rules of Engagement |
| **SOW** | Statement of Work |
| **MSA** | Master Service Agreement |
| **Authorization Letter** | Legal permission to test |

---

## 1.9 Information Security Policies

### Types of Policies

| Policy Type | Description |
|-------------|-------------|
| **Promiscuous** | No restrictions |
| **Permissive** | Minimal restrictions |
| **Prudent** | Maximum security with usability |
| **Paranoid** | Extreme restrictions |

### Common Security Policies
- [ ] Acceptable Use Policy (AUP)
- [ ] Password Policy
- [ ] Access Control Policy
- [ ] Remote Access Policy
- [ ] Incident Response Policy
- [ ] BYOD Policy
- [ ] Data Classification Policy

---

## Quick Revision Table

| Topic | Key Points |
|-------|------------|
| CIA Triad | Confidentiality, Integrity, Availability |
| Hacker Types | White, Black, Gray, Script Kiddies, etc. |
| Hacking Phases | Recon → Scan → Access → Maintain → Clear |
| Kill Chain | 7 stages from Recon to Actions |
| Controls | Physical, Technical, Administrative |
| Testing Types | Black Box, White Box, Gray Box |

---

## Key Terms Glossary

| Term | Definition |
|------|------------|
| CIA Triad | Confidentiality, Integrity, Availability |
| Ethical Hacking | Authorized security testing |
| Cyber Kill Chain | 7 stages of attack |
| Defense in Depth | Multiple security layers |
| Black Box Testing | No prior knowledge |
| White Box Testing | Full knowledge |
| Gray Box Testing | Partial knowledge |
| APT | Advanced Persistent Threat |
| OSINT | Open Source Intelligence |
| C2 | Command and Control |
