
#                 PHASE 1: PREREQUISITES
# ═══════════════════════════════════════════════════════


## 1.1 Networking Fundamentals

### OSI Model
- [ ] Layer 1 - Physical (Cables, Hubs)
- [ ] Layer 2 - Data Link (MAC, Switches, ARP)
- [ ] Layer 3 - Network (IP, Routers, ICMP)
- [ ] Layer 4 - Transport (TCP, UDP, Ports)
- [ ] Layer 5 - Session (Sessions, Authentication)
- [ ] Layer 6 - Presentation (Encryption, Compression)
- [ ] Layer 7 - Application (HTTP, FTP, DNS)

### TCP/IP Model
- [ ] Network Access Layer
- [ ] Internet Layer
- [ ] Transport Layer
- [ ] Application Layer
- [ ] TCP vs UDP differences
- [ ] TCP 3-way handshake (SYN, SYN-ACK, ACK)
- [ ] TCP flags (SYN, ACK, FIN, RST, PSH, URG)

### IP Addressing
- [x] IPv4 addressing
- [x] IPv6 basics
- [x] Public vs Private IPs
- [x] Subnetting (CIDR notation)
- [x] Calculate network/host portions
- [x] Subnet masks
- [x] NAT (Network Address Translation)
- [x] DHCP working

### Common Protocols
- [ ] HTTP/HTTPS (Port 80/443)
- [ ] FTP (Port 21)
- [ ] SSH (Port 22)
- [ ] Telnet (Port 23)
- [ ] SMTP (Port 25)
- [ ] DNS (Port 53)
- [ ] TFTP (Port 69)
- [ ] POP3 (Port 110)
- [ ] IMAP (Port 143)
- [ ] SNMP (Port 161/162)
- [ ] LDAP (Port 389)
- [ ] SMB (Port 445)
- [ ] RDP (Port 3389)
- [ ] MySQL (Port 3306)
- [ ] PostgreSQL (Port 5432)
- [ ] MongoDB (Port 27017)

### Network Security Devices
- [ ] Firewalls (Stateful vs Stateless)
- [ ] IDS (Intrusion Detection System)
- [ ] IPS (Intrusion Prevention System)
- [ ] WAF (Web Application Firewall)
- [ ] Proxy servers
- [ ] Load balancers
- [ ] VPN (Virtual Private Network)

### Network Analysis
- [ ] Wireshark basics
- [ ] Packet capture and analysis
- [ ] Filter expressions in Wireshark
- [ ] tcpdump usage
- [ ] Network traffic analysis

### Practical Skills
- [ ] Ping, traceroute, netstat commands
- [ ] nslookup, dig for DNS
- [ ] arp -a for ARP table
- [ ] netcat (nc) usage
- [ ] curl and wget


## 1.2 Operating Systems

### Linux Fundamentals
- [ ] Linux file system hierarchy (/etc, /var, /home, /tmp, /opt)
- [ ] File permissions (chmod, chown, chgrp)
- [ ] Read/Write/Execute permissions
- [ ] SUID, SGID, Sticky bit
- [ ] User and group management
- [ ] Package management (apt, yum, pacman)
- [ ] Process management (ps, top, htop, kill)
- [ ] Service management (systemctl, service)
- [ ] Cron jobs and scheduled tasks
- [ ] Environment variables
- [ ] SSH key authentication
- [ ] Log files (/var/log/)
- [ ] Network configuration
- [ ] iptables/firewalld basics

### Essential Linux Commands
- [ ] Navigation: cd, ls, pwd, find, locate
- [ ] File operations: cp, mv, rm, mkdir, touch
- [ ] Text processing: cat, less, head, tail, grep
- [ ] Text editors: nano, vim basics
- [ ] Permissions: chmod, chown
- [ ] Archiving: tar, zip, unzip, gzip
- [ ] Networking: ifconfig, ip, ss, netstat
- [ ] Download: wget, curl
- [ ] Process: ps, kill, bg, fg, jobs
- [ ] Disk: df, du, mount
- [ ] Search: find, grep, awk, sed

### Kali/Parrot Linux
- [ ] Installation and setup
- [ ] Tool categories and locations
- [ ] Updating and upgrading
- [ ] Installing additional tools
- [ ] Virtual machine setup

### Windows Fundamentals
- [ ] Windows file system (C:\, System32, Users)
- [ ] Registry basics (HKLM, HKCU, HKCR)
- [ ] Windows services
- [ ] User account types
- [ ] UAC (User Account Control)
- [ ] Windows Defender basics
- [ ] Event Viewer
- [ ] Task Manager and Resource Monitor
- [ ] Windows Firewall

### Windows Command Line (CMD)
- [ ] dir, cd, copy, move, del
- [ ] ipconfig, netstat, arp
- [ ] net user, net localgroup
- [ ] tasklist, taskkill
- [ ] systeminfo
- [ ] wmic commands
- [ ] sc (service control)
- [ ] reg (registry)
- [ ] icacls (permissions)

### Windows PowerShell
- [ ] Basic cmdlets (Get-*, Set-*, New-*)
- [ ] Get-Process, Get-Service
- [ ] Get-NetTCPConnection
- [ ] Get-LocalUser, Get-LocalGroup
- [ ] Pipeline operations
- [ ] Execution policies
- [ ] PowerShell scripting basics
- [ ] Remote PowerShell

### Active Directory Basics
- [ ] Domain, Forest, Tree concepts
- [ ] Domain Controller
- [ ] Users, Groups, OUs
- [ ] Group Policies (GPO)
- [ ] Kerberos authentication
- [ ] NTLM authentication
- [ ] Trust relationships
- [ ] DNS in AD


## 1.3 Programming & Scripting

### Python
- [ ] Variables and data types
- [ ] Strings and string manipulation
- [ ] Lists, tuples, dictionaries, sets
- [ ] Conditional statements (if/elif/else)
- [ ] Loops (for, while)
- [ ] Functions and modules
- [ ] File I/O operations
- [ ] Exception handling
- [ ] Regular expressions (re module)
- [ ] Requests library (HTTP requests)
- [ ] Socket programming basics
- [ ] Beautiful Soup (web scraping)
- [ ] Subprocess module
- [ ] Writing simple exploits
- [ ] Automation scripts

### Bash Scripting
- [ ] Shebang (#!/bin/bash)
- [ ] Variables and arguments ($1, $2, $@)
- [ ] Conditional statements
- [ ] Loops (for, while)
- [ ] Functions
- [ ] Input/Output redirection
- [ ] Pipes
- [ ] grep, awk, sed in scripts
- [ ] File testing (-f, -d, -r, -w, -x)
- [ ] Exit codes
- [ ] Automation scripts

### SQL (Database)
- [ ] SELECT, INSERT, UPDATE, DELETE
- [ ] WHERE, ORDER BY, GROUP BY
- [ ] JOIN operations (INNER, LEFT, RIGHT)
- [ ] UNION statements
- [ ] Subqueries
- [ ] SQL functions
- [ ] Database structure (tables, columns)
- [ ] MySQL/PostgreSQL basics
- [ ] SQL injection understanding

### JavaScript
- [ ] Variables (var, let, const)
- [ ] Data types
- [ ] Functions and arrow functions
- [ ] DOM manipulation
- [ ] Event handlers
- [ ] document.cookie
- [ ] XMLHttpRequest / Fetch API
- [ ] AJAX requests
- [ ] localStorage/sessionStorage
- [ ] Understanding XSS payloads

### Web Technologies
- [ ] HTML basics
- [ ] HTTP methods (GET, POST, PUT, DELETE)
- [ ] HTTP headers
- [ ] HTTP status codes
- [ ] Cookies and sessions
- [ ] REST API concepts
- [ ] JSON format


# ═══════════════════════════════════════════════════════
#                 PHASE 2: CORE VAPT CONCEPTS
# ═══════════════════════════════════════════════════════


## 2.1 Understanding VAPT

### Vulnerability Assessment
- [ ] Definition and purpose
- [ ] Automated scanning
- [ ] Identifying vulnerabilities
- [ ] Risk rating
- [ ] Reporting findings
- [ ] Difference from penetration testing

### Penetration Testing
- [ ] Definition and purpose
- [ ] Manual exploitation
- [ ] Proving vulnerabilities are exploitable
- [ ] Business impact demonstration
- [ ] Ethical hacking principles

### Types of Testing
- [ ] Black Box (no prior knowledge)
- [ ] White Box (full knowledge, source code)
- [ ] Grey Box (partial knowledge)
- [ ] External testing
- [ ] Internal testing
- [ ] Blind testing
- [ ] Double-blind testing

### Engagement Types
- [ ] Network penetration testing
- [ ] Web application testing
- [ ] Mobile application testing
- [ ] Wireless penetration testing
- [ ] Social engineering
- [ ] Physical penetration testing
- [ ] Cloud security testing
- [ ] Red team vs Blue team


## 2.2 Methodologies & Frameworks

### OWASP Testing Guide
- [ ] Information Gathering
- [ ] Configuration Management Testing
- [ ] Identity Management Testing
- [ ] Authentication Testing
- [ ] Authorization Testing
- [ ] Session Management Testing
- [ ] Input Validation Testing
- [ ] Error Handling Testing
- [ ] Cryptography Testing
- [ ] Business Logic Testing
- [ ] Client-side Testing

### PTES (Penetration Testing Execution Standard)
- [ ] Pre-engagement Interactions
- [ ] Intelligence Gathering
- [ ] Threat Modeling
- [ ] Vulnerability Analysis
- [ ] Exploitation
- [ ] Post-Exploitation
- [ ] Reporting

### NIST SP 800-115
- [ ] Planning
- [ ] Discovery
- [ ] Attack
- [ ] Reporting

### OSSTMM
- [ ] Security metrics
- [ ] Operational security
- [ ] Human security
- [ ] Physical security
- [ ] Telecommunications security
- [ ] Data networks security

### Other Standards
- [ ] ISSAF (Information Systems Security Assessment Framework)
- [ ] CREST guidelines
- [ ] PCI DSS testing requirements
- [ ] ISO 27001 awareness


## 2.3 Legal & Ethical Considerations

### Legal Aspects
- [ ] Rules of engagement (ROE)
- [ ] Scope definition
- [ ] Written authorization/permission
- [ ] NDA (Non-Disclosure Agreement)
- [ ] MSA (Master Service Agreement)
- [ ] Liability clauses
- [ ] Data handling requirements
- [ ] Emergency contact procedures

### Ethical Guidelines
- [ ] Only test with permission
- [ ] Stay within scope
- [ ] Report all findings
- [ ] Protect sensitive data
- [ ] Do no harm principle
- [ ] Responsible disclosure


# ══════════════════════════════════════════════════════════════
#                 PHASE 3: INFORMATION GATHERING
# ══════════════════════════════════════════════════════════════


## 3.1 Passive Reconnaissance

### OSINT (Open Source Intelligence)
- [ ] Company website analysis
- [ ] About us, Contact pages
- [ ] Employee information
- [ ] Technology stack identification
- [ ] Press releases and news

### Domain Information
- [ ] WHOIS lookup
- [ ] Domain registration details
- [ ] Registrar information
- [ ] Historical WHOIS data
- [ ] Reverse WHOIS lookup

### DNS Enumeration
- [ ] DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA)
- [ ] Zone transfer attempts (AXFR)
- [ ] Subdomain enumeration
- [ ] DNS history
- [ ] Reverse DNS lookup
- [ ] Tools: dig, nslookup, host, dnsrecon

### Search Engine Reconnaissance
- [ ] Google Dorking
- [ ] site: operator
- [ ] filetype: operator
- [ ] inurl: operator
- [ ] intitle: operator
- [ ] intext: operator
- [ ] cache: operator
- [ ] Bing dorking
- [ ] DuckDuckGo

### Google Dork Examples
- [ ] site:target.com filetype:pdf
- [ ] site:target.com inurl:admin
- [ ] site:target.com intitle:"index of"
- [ ] site:target.com ext:sql | ext:db
- [ ] site:target.com intext:password
- [ ] "target.com" filetype:log
- [ ] site:pastebin.com "target.com"

### Internet Archives
- [ ] Wayback Machine (archive.org)
- [ ] Historical website versions
- [ ] Old files and directories
- [ ] Removed content

### Certificate Transparency
- [ ] crt.sh
- [ ] Censys certificates
- [ ] SSL certificate analysis
- [ ] Subdomain discovery via certs

### Social Media OSINT
- [ ] LinkedIn (employees, tech stack)
- [ ] Twitter/X
- [ ] Facebook
- [ ] GitHub (code leaks, employees)
- [ ] Stack Overflow
- [ ] Job postings (technology hints)

### Code Repositories
- [ ] GitHub searching
- [ ] GitLab public repos
- [ ] Bitbucket
- [ ] Exposed credentials in code
- [ ] API keys in commits
- [ ] .git folder exposure

### Data Breach Information
- [ ] HaveIBeenPwned
- [ ] Dehashed
- [ ] Breach databases
- [ ] Credential leaks

### Passive Recon Tools
- [ ] theHarvester
- [ ] Maltego
- [ ] Shodan
- [ ] Censys
- [ ] Recon-ng
- [ ] SpiderFoot
- [ ] FOCA
- [ ] Amass (passive mode)


## 3.2 Active Reconnaissance

### Network Discovery
- [ ] Ping sweeps
- [ ] ARP scanning
- [ ] Host discovery
- [ ] Network mapping

### Port Scanning
- [ ] TCP connect scan
- [ ] SYN scan (stealth)
- [ ] UDP scan
- [ ] ACK scan
- [ ] FIN/NULL/Xmas scans
- [ ] Top ports scanning
- [ ] Full port scan (1-65535)

### Nmap Essential Scans
- [ ] nmap -sn (host discovery)
- [ ] nmap -sT (TCP connect)
- [ ] nmap -sS (SYN stealth)
- [ ] nmap -sU (UDP scan)
- [ ] nmap -sV (version detection)
- [ ] nmap -O (OS detection)
- [ ] nmap -A (aggressive scan)
- [ ] nmap -sC (default scripts)
- [ ] nmap --script=vuln
- [ ] nmap -p- (all ports)
- [ ] nmap -T4 (timing template)

### Banner Grabbing
- [ ] netcat banner grabbing
- [ ] Telnet banner grabbing
- [ ] Nmap service detection
- [ ] WhatWeb for web apps

### Subdomain Enumeration
- [ ] Sublist3r
- [ ] Amass
- [ ] Subfinder
- [ ] Assetfinder
- [ ] Knockpy
- [ ] DNSenum
- [ ] Fierce
- [ ] Brute force subdomains

### Directory/File Enumeration
- [ ] Gobuster
- [ ] Dirb
- [ ] Dirbuster
- [ ] ffuf
- [ ] Feroxbuster
- [ ] Common wordlists (SecLists)

### Web Application Fingerprinting
- [ ] Wappalyzer
- [ ] WhatWeb
- [ ] BuiltWith
- [ ] Technology identification
- [ ] CMS detection (WPScan, CMSmap)
- [ ] Web server identification

### Email Harvesting
- [ ] theHarvester
- [ ] Hunter.io
- [ ] Email format identification
- [ ] Phonebook.cz
- [ ] Clearbit


# ══════════════════════════════════════════════════════════════
#                 PHASE 4: SCANNING & ENUMERATION
# ══════════════════════════════════════════════════════════════


## 4.1 Port & Service Scanning

### TCP Port Scanning
- [ ] Well-known ports (0-1023)
- [ ] Registered ports (1024-49151)
- [ ] Dynamic ports (49152-65535)
- [ ] Service to port mapping
- [ ] Nmap scan techniques
- [ ] Masscan for speed
- [ ] RustScan for speed

### UDP Port Scanning
- [ ] Common UDP services
- [ ] DNS (53)
- [ ] DHCP (67, 68)
- [ ] TFTP (69)
- [ ] SNMP (161, 162)
- [ ] NTP (123)
- [ ] UDP scan challenges


## 4.2 Service Enumeration

### SMB Enumeration (Port 445, 139)
- [ ] smbclient -L
- [ ] enum4linux
- [ ] smbmap
- [ ] crackmapexec smb
- [ ] nmap smb scripts
- [ ] Null session enumeration
- [ ] Share enumeration
- [ ] User enumeration
- [ ] SMB vulnerabilities (EternalBlue)

### NetBIOS Enumeration (Port 137, 138, 139)
- [ ] nbtscan
- [ ] nbtstat
- [ ] nmblookup

### LDAP Enumeration (Port 389, 636)
- [ ] ldapsearch
- [ ] ldapenum
- [ ] nmap ldap scripts
- [ ] Anonymous bind testing
- [ ] User/group enumeration

### SNMP Enumeration (Port 161)
- [ ] snmpwalk
- [ ] snmp-check
- [ ] onesixtyone
- [ ] Community string brute force
- [ ] MIB tree enumeration
- [ ] System information extraction

### DNS Enumeration (Port 53)
- [ ] Zone transfer (AXFR)
- [ ] DNS brute force
- [ ] dnsenum
- [ ] dnsrecon
- [ ] Reverse lookup

### NFS Enumeration (Port 2049)
- [ ] showmount -e
- [ ] nmap nfs scripts
- [ ] Mount shares
- [ ] File access testing

### SMTP Enumeration (Port 25)
- [ ] VRFY command
- [ ] EXPN command
- [ ] RCPT TO enumeration
- [ ] smtp-user-enum
- [ ] nmap smtp scripts

### FTP Enumeration (Port 21)
- [ ] Anonymous login
- [ ] Banner grabbing
- [ ] Version detection
- [ ] nmap ftp scripts

### SSH Enumeration (Port 22)
- [ ] Version detection
- [ ] Supported algorithms
- [ ] ssh-audit
- [ ] User enumeration (CVE-2018-15473)

### RDP Enumeration (Port 3389)
- [ ] Version detection
- [ ] NLA status
- [ ] BlueKeep vulnerability
- [ ] nmap rdp scripts

### MySQL Enumeration (Port 3306)
- [ ] Version detection
- [ ] Remote access testing
- [ ] Default credentials
- [ ] nmap mysql scripts

### MSSQL Enumeration (Port 1433)
- [ ] Version detection
- [ ] nmap ms-sql scripts
- [ ] xp_cmdshell testing
- [ ] Default SA credentials

### Oracle Enumeration (Port 1521)
- [ ] TNS listener
- [ ] SID enumeration
- [ ] oscanner
- [ ] nmap oracle scripts

### Redis Enumeration (Port 6379)
- [ ] redis-cli
- [ ] Unauthenticated access
- [ ] Data dumping
- [ ] SSH key injection

### MongoDB Enumeration (Port 27017)
- [ ] Unauthenticated access
- [ ] Database enumeration
- [ ] Data extraction


## 4.3 Vulnerability Scanning

### Network Vulnerability Scanners
- [ ] Nessus
- [ ] OpenVAS
- [ ] Nexpose
- [ ] Qualys
- [ ] Nmap NSE scripts

### Web Vulnerability Scanners
- [ ] Nikto
- [ ] Nuclei
- [ ] OWASP ZAP
- [ ] Burp Suite Scanner
- [ ] Acunetix
- [ ] Netsparker

### Vulnerability Identification
- [ ] CVE identification
- [ ] CVSS scoring understanding
- [ ] Exploit availability check
- [ ] False positive verification


# ═══════════════════════════════════════════════════════
#                 PHASE 5: VULNERABILITY ASSESSMENT
# ═══════════════════════════════════════════════════════


## 5.1 Vulnerability Identification

### CVE/CWE Understanding
- [ ] CVE (Common Vulnerabilities and Exposures)
- [ ] CWE (Common Weakness Enumeration)
- [ ] NVD (National Vulnerability Database)
- [ ] Exploit-DB
- [ ] CVE Details
- [ ] Mitre ATT&CK framework

### CVSS Scoring
- [ ] CVSS v3.1 understanding
- [ ] Attack Vector (Network/Adjacent/Local/Physical)
- [ ] Attack Complexity (Low/High)
- [ ] Privileges Required (None/Low/High)
- [ ] User Interaction (None/Required)
- [ ] Scope (Changed/Unchanged)
- [ ] Impact metrics (CIA)
- [ ] CVSS calculator usage

### Risk Assessment
- [ ] Likelihood of exploitation
- [ ] Business impact analysis
- [ ] Asset criticality
- [ ] Risk prioritization
- [ ] Risk matrix (Likelihood x Impact)


## 5.2 Vulnerability Verification

### Manual Verification
- [ ] Validate scanner findings
- [ ] Eliminate false positives
- [ ] Proof of concept development
- [ ] Impact assessment
- [ ] Exploitability confirmation

### Vulnerability Databases
- [ ] Exploit-DB
- [ ] Searchsploit
- [ ] Packet Storm
- [ ] Rapid7 Vulnerability DB
- [ ] VulDB
- [ ] Snyk Vulnerability DB


# ═══════════════════════════════════════════════════════
#                    PHASE 6: EXPLOITATION
# ═══════════════════════════════════════════════════════


## 6.1 Exploitation Frameworks

### Metasploit Framework
- [ ] msfconsole basics
- [ ] Module types (exploit, auxiliary, post, payload)
- [ ] search command
- [ ] use command
- [ ] show options
- [ ] set/setg commands
- [ ] run/exploit command
- [ ] Payload selection
- [ ] Meterpreter basics
- [ ] Sessions management
- [ ] MSFvenom for payload generation
- [ ] Handlers (multi/handler)

### Meterpreter Commands
- [ ] sysinfo
- [ ] getuid
- [ ] getsystem
- [ ] hashdump
- [ ] upload/download
- [ ] shell
- [ ] migrate
- [ ] ps
- [ ] screenshot
- [ ] keyscan_start/stop
- [ ] portfwd
- [ ] route


## 6.2 Manual Exploitation

### Exploit Research
- [ ] Searchsploit usage
- [ ] Exploit-DB manual search
- [ ] GitHub exploit search
- [ ] Google for PoCs
- [ ] Adapting exploits

### Common Exploits
- [ ] EternalBlue (MS17-010)
- [ ] BlueKeep (CVE-2019-0708)
- [ ] PrintNightmare
- [ ] Log4Shell
- [ ] ShellShock
- [ ] Heartbleed
- [ ] DirtyCow


## 6.3 Password Attacks

### Online Attacks (Brute Force)
- [ ] Hydra
- [ ] Medusa
- [ ] Ncrack
- [ ] Crowbar
- [ ] Patator
- [ ] Burp Intruder

### Hydra Examples
- [ ] SSH brute force
- [ ] FTP brute force
- [ ] HTTP form brute force
- [ ] RDP brute force
- [ ] SMB brute force

### Offline Attacks (Hash Cracking)
- [ ] John the Ripper
- [ ] Hashcat
- [ ] Hash identification (hashid, hash-identifier)
- [ ] Wordlist attacks
- [ ] Rule-based attacks
- [ ] Mask attacks
- [ ] Rainbow tables

### Common Hash Types
- [ ] MD5
- [ ] SHA1, SHA256, SHA512
- [ ] NTLM
- [ ] NTLMv2
- [ ] Kerberos TGS (Kerberoasting)
- [ ] bcrypt
- [ ] Linux shadow hashes

### Wordlists
- [ ] rockyou.txt
- [ ] SecLists
- [ ] Custom wordlist generation (CeWL, Crunch)
- [ ] Username wordlists

### Password Spraying
- [ ] Concept understanding
- [ ] Common passwords list
- [ ] Lockout policy awareness
- [ ] Tools (crackmapexec, sprayhound)


## 6.4 Shells & Payloads

### Reverse Shells
- [ ] Bash reverse shell
- [ ] Python reverse shell
- [ ] PHP reverse shell
- [ ] PowerShell reverse shell
- [ ] Netcat reverse shell
- [ ] Perl reverse shell
- [ ] Ruby reverse shell

### Bind Shells
- [ ] Concept understanding
- [ ] Netcat bind shell
- [ ] When to use bind vs reverse

### Web Shells
- [ ] PHP web shell
- [ ] ASPX web shell
- [ ] JSP web shell
- [ ] Web shell upload techniques

### Payload Generation
- [ ] MSFvenom usage
- [ ] Staged vs Stageless payloads
- [ ] Encoders and evasion
- [ ] Platform-specific payloads

### Shell Stabilization
- [ ] Python PTY spawn
- [ ] stty raw -echo; fg
- [ ] rlwrap usage
- [ ] Upgrading shells


# ═══════════════════════════════════════════════════════
#               PHASE 7: WEB APPLICATION TESTING
# ═══════════════════════════════════════════════════════


## 7.1 Web Application Basics

### HTTP Fundamentals
- [ ] HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- [ ] HTTP headers (Request & Response)
- [ ] HTTP status codes (1xx, 2xx, 3xx, 4xx, 5xx)
- [ ] HTTP vs HTTPS
- [ ] SSL/TLS basics
- [ ] HTTP/2 and HTTP/3

### Session Management
- [ ] Cookies
- [ ] Session tokens
- [ ] Session ID analysis
- [ ] Session fixation
- [ ] Session hijacking
- [ ] Cookie attributes (HttpOnly, Secure, SameSite)

### Authentication Mechanisms
- [ ] Form-based authentication
- [ ] Basic authentication
- [ ] Digest authentication
- [ ] Token-based (JWT)
- [ ] OAuth 2.0
- [ ] SAML
- [ ] Multi-factor authentication (MFA)


## 7.2 OWASP Top 10 (2021)

### A01 - Broken Access Control
- [ ] IDOR (Insecure Direct Object Reference)
- [ ] Horizontal privilege escalation
- [ ] Vertical privilege escalation
- [ ] Missing function level access control
- [ ] Directory traversal
- [ ] Forced browsing
- [ ] Metadata manipulation
- [ ] CORS misconfiguration

### A02 - Cryptographic Failures
- [ ] Data transmitted in cleartext
- [ ] Weak cryptographic algorithms
- [ ] Weak key generation
- [ ] Missing encryption
- [ ] Improper certificate validation
- [ ] Deprecated hash functions
- [ ] Hardcoded keys/credentials

### A03 - Injection
- [ ] SQL Injection (Classic, Error-based, Blind, Time-based)
- [ ] Union-based SQLi
- [ ] Stacked queries
- [ ] Second-order SQLi
- [ ] NoSQL injection
- [ ] Command injection
- [ ] LDAP injection
- [ ] XPath injection
- [ ] Template injection (SSTI)
- [ ] Header injection
- [ ] Log injection

### SQL Injection Deep Dive
- [ ] Detection techniques
- [ ] Manual exploitation
- [ ] SQLmap usage
- [ ] Bypassing WAF
- [ ] Reading files
- [ ] Writing files
- [ ] OS command execution
- [ ] Database enumeration

### A04 - Insecure Design
- [ ] Business logic flaws
- [ ] Lack of rate limiting
- [ ] Race conditions
- [ ] Missing security controls
- [ ] Trust boundary violations

### A05 - Security Misconfiguration
- [ ] Default credentials
- [ ] Unnecessary features enabled
- [ ] Verbose error messages
- [ ] Unpatched systems
- [ ] Insecure default configurations
- [ ] Missing security headers
- [ ] Directory listing
- [ ] Exposed admin interfaces

### Security Headers Check
- [ ] Content-Security-Policy (CSP)
- [ ] X-Frame-Options
- [ ] X-Content-Type-Options
- [ ] Strict-Transport-Security (HSTS)
- [ ] X-XSS-Protection
- [ ] Referrer-Policy
- [ ] Permissions-Policy

### A06 - Vulnerable and Outdated Components
- [ ] Identifying component versions
- [ ] CVE searching
- [ ] Dependency checking
- [ ] Software composition analysis
- [ ] Retire.js (JavaScript)
- [ ] Dependency-check tools

### A07 - Identification and Authentication Failures
- [ ] Weak passwords allowed
- [ ] Credential stuffing
- [ ] Brute force attacks
- [ ] Session ID in URL
- [ ] Session fixation
- [ ] Insecure password recovery
- [ ] Missing MFA
- [ ] Username enumeration

### A08 - Software and Data Integrity Failures
- [ ] Insecure deserialization
- [ ] Java deserialization
- [ ] PHP deserialization
- [ ] Python pickle
- [ ] .NET deserialization
- [ ] CI/CD pipeline attacks
- [ ] Auto-update without verification
- [ ] Unsigned code

### A09 - Security Logging and Monitoring Failures
- [ ] Insufficient logging
- [ ] Logs not monitored
- [ ] Sensitive data in logs
- [ ] Missing audit trails
- [ ] No alerting mechanism

### A10 - Server-Side Request Forgery (SSRF)
- [ ] Basic SSRF
- [ ] Blind SSRF
- [ ] Cloud metadata access (169.254.169.254)
- [ ] Internal port scanning
- [ ] Accessing internal services
- [ ] Protocol smuggling
- [ ] Bypass techniques


## 7.3 Additional Web Vulnerabilities

### Cross-Site Scripting (XSS)
- [ ] Reflected XSS
- [ ] Stored XSS
- [ ] DOM-based XSS
- [ ] Self-XSS
- [ ] XSS filter bypass
- [ ] XSS contexts (HTML, JS, attribute)
- [ ] XSS payloads
- [ ] Cookie stealing
- [ ] Session hijacking via XSS
- [ ] Keylogging via XSS

### Cross-Site Request Forgery (CSRF)
- [ ] CSRF understanding
- [ ] CSRF token bypass
- [ ] Same-site cookie bypass
- [ ] CSRF via XSS
- [ ] JSON CSRF

### XML External Entity (XXE)
- [ ] Basic XXE
- [ ] Blind XXE
- [ ] XXE to SSRF
- [ ] XXE file reading
- [ ] XXE out-of-band
- [ ] Parameter entity injection

### File Upload Vulnerabilities
- [ ] Unrestricted file upload
- [ ] Extension bypass (.php5, .phtml, .pHp)
- [ ] Content-Type bypass
- [ ] Magic bytes bypass
- [ ] Double extension
- [ ] Null byte injection
- [ ] Path traversal in filename
- [ ] Polyglot files

### File Inclusion
- [ ] Local File Inclusion (LFI)
- [ ] Remote File Inclusion (RFI)
- [ ] LFI to RCE techniques
- [ ] Log poisoning
- [ ] PHP wrappers (php://filter, php://input)
- [ ] /proc/self/environ

### Server-Side Template Injection (SSTI)
- [ ] Detection techniques
- [ ] Jinja2 (Python)
- [ ] Twig (PHP)
- [ ] Freemarker (Java)
- [ ] Velocity (Java)
- [ ] Pebble (Java)
- [ ] RCE via SSTI

### HTTP Request Smuggling
- [ ] CL.TE vulnerability
- [ ] TE.CL vulnerability
- [ ] TE.TE vulnerability
- [ ] Request smuggling attacks
- [ ] Cache poisoning via smuggling

### WebSocket Vulnerabilities
- [ ] WebSocket security
- [ ] Cross-site WebSocket hijacking
- [ ] WebSocket message manipulation

### JWT Attacks
- [ ] None algorithm attack
- [ ] Algorithm confusion (RS256 to HS256)
- [ ] Weak secret brute force
- [ ] JKU/X5U header injection
- [ ] Kid header path traversal
- [ ] JWT tools (jwt_tool)

### GraphQL Security
- [ ] Introspection enabled
- [ ] Injection attacks
- [ ] Authorization flaws
- [ ] Rate limiting bypass
- [ ] Batching attacks

### API Security
- [ ] OWASP API Top 10
- [ ] Broken Object Level Authorization (BOLA)
- [ ] Broken User Authentication
- [ ] Excessive Data Exposure
- [ ] Lack of Resources & Rate Limiting
- [ ] Broken Function Level Authorization
- [ ] Mass Assignment
- [ ] Security Misconfiguration
- [ ] Injection
- [ ] Improper Assets Management
- [ ] Insufficient Logging


## 7.4 Web Application Tools

### Proxy Tools
- [ ] Burp Suite (MASTER THIS)
  - [ ] Proxy setup
  - [ ] Intercepting requests
  - [ ] Repeater
  - [ ] Intruder
  - [ ] Decoder
  - [ ] Comparer
  - [ ] Sequencer
  - [ ] Extensions (Autorize, Logger++)
- [ ] OWASP ZAP
- [ ] mitmproxy

### Fuzzing Tools
- [ ] ffuf
- [ ] wfuzz
- [ ] Gobuster
- [ ] Feroxbuster
- [ ] Dirb/Dirbuster

### SQL Injection Tools
- [ ] SQLmap (all options)
- [ ] Manual techniques
- [ ] BBQSQL
- [ ] NoSQLmap

### XSS Tools
- [ ] XSStrike
- [ ] XSSer
- [ ] Dalfox
- [ ] Manual testing

### Other Tools
- [ ] Nikto
- [ ] Nuclei
- [ ] WPScan (WordPress)
- [ ] CMSmap
- [ ] Droopescan (Drupal)
- [ ] Joomscan (Joomla)

### Wordlists
- [ ] SecLists
- [ ] PayloadsAllTheThings
- [ ] FuzzDB
- [ ] Custom wordlists


# ═══════════════════════════════════════════════════════
#              PHASE 8: NETWORK PENETRATION TESTING
# ═══════════════════════════════════════════════════════


## 8.1 External Network Testing

### Perimeter Testing
- [ ] External IP enumeration
- [ ] Port scanning external assets
- [ ] Service enumeration
- [ ] Vulnerability identification
- [ ] Firewall rule identification
- [ ] IDS/IPS evasion

### Firewall Bypass Techniques
- [ ] Port hopping
- [ ] Protocol encapsulation
- [ ] Fragmentation
- [ ] Source port manipulation
- [ ] HTTP/HTTPS tunneling


## 8.2 Internal Network Testing

### Initial Access
- [ ] Phishing (if in scope)
- [ ] Exploiting public services
- [ ] Password attacks
- [ ] VPN vulnerabilities

### Network Sniffing
- [ ] ARP spoofing
- [ ] LLMNR/NBT-NS poisoning
- [ ] Responder tool
- [ ] MITM attacks
- [ ] Bettercap

### Lateral Movement
- [ ] Pass-the-Hash
- [ ] Pass-the-Ticket
- [ ] Overpass-the-Hash
- [ ] Token impersonation
- [ ] RDP
- [ ] WMI
- [ ] WinRM
- [ ] PSExec
- [ ] SMB
- [ ] SSH

### Active Directory Attacks

#### Enumeration
- [ ] BloodHound setup and usage
- [ ] SharpHound data collection
- [ ] PowerView
- [ ] AD Explorer
- [ ] ldapdomaindump
- [ ] enum4linux-ng
- [ ] User enumeration
- [ ] Group enumeration
- [ ] Computer enumeration
- [ ] GPO enumeration
- [ ] Trust enumeration
- [ ] ACL enumeration

#### Credential Attacks
- [ ] Kerberoasting
- [ ] AS-REP Roasting
- [ ] Password spraying
- [ ] NTLM relay
- [ ] LDAP relay
- [ ] Credential dumping
- [ ] LSASS dumping
- [ ] SAM database extraction
- [ ] Mimikatz usage
- [ ] DCSync attack

#### Privilege Escalation
- [ ] Token impersonation
- [ ] SeBackupPrivilege abuse
- [ ] SeImpersonatePrivilege abuse
- [ ] DNSAdmin abuse
- [ ] Group Policy abuse
- [ ] Print Spooler attacks
- [ ] Resource-based constrained delegation
- [ ] Unconstrained delegation
- [ ] Constrained delegation

#### Domain Compromise
- [ ] Golden Ticket attack
- [ ] Silver Ticket attack
- [ ] Skeleton Key attack
- [ ] DSRM abuse
- [ ] Domain persistence
- [ ] Forest compromise
- [ ] Cross-domain attacks

#### AD Tools
- [ ] Impacket suite
  - [ ] secretsdump.py
  - [ ] GetUserSPNs.py
  - [ ] GetNPUsers.py
  - [ ] psexec.py
  - [ ] wmiexec.py
  - [ ] smbexec.py
  - [ ] dcomexec.py
  - [ ] ntlmrelayx.py
- [ ] CrackMapExec
- [ ] Evil-WinRM
- [ ] Rubeus
- [ ] Mimikatz
- [ ] BloodHound
- [ ] PowerSploit
- [ ] ADModule
- [ ] Kerbrute


## 8.3 Wireless Penetration Testing

### Wireless Basics
- [ ] 802.11 standards
- [ ] Frequency bands (2.4GHz, 5GHz)
- [ ] Wireless encryption (WEP, WPA, WPA2, WPA3)
- [ ] SSID and BSSID
- [ ] Handshake process

### Wireless Attacks
- [ ] Deauthentication attack
- [ ] WEP cracking
- [ ] WPA/WPA2 PSK cracking
- [ ] WPA2 Enterprise attacks
- [ ] PMKID attack
- [ ] Evil Twin attack
- [ ] Captive portal attack
- [ ] Karma attack
- [ ] Rogue access point
- [ ] WPS attacks (Reaver)
- [ ] Krack attack

### Wireless Tools
- [ ] Aircrack-ng suite
  - [ ] airmon-ng
  - [ ] airodump-ng
  - [ ] aireplay-ng
  - [ ] aircrack-ng
- [ ] Wifite
- [ ] Bettercap
- [ ] Fluxion
- [ ] Hostapd-wpe
- [ ] hcxdumptool
- [ ] hcxtools


## 8.4 Pivoting & Tunneling

### Port Forwarding
- [ ] Local port forwarding (SSH -L)
- [ ] Remote port forwarding (SSH -R)
- [ ] Dynamic port forwarding (SSH -D)

### Tunneling Tools
- [ ] Chisel
- [ ] Ligolo-ng
- [ ] sshuttle
- [ ] Proxychains
- [ ] socat
- [ ] plink.exe (Windows)
- [ ] netsh (Windows)

### Network Pivoting
- [ ] Meterpreter pivoting
- [ ] Route adding
- [ ] Multi-level pivoting
- [ ] Double pivoting


# ═══════════════════════════════════════════════════════
#                  PHASE 9: POST EXPLOITATION
# ═══════════════════════════════════════════════════════


## 9.1 Linux Privilege Escalation

### Enumeration
- [ ] whoami, id, hostname
- [ ] uname -a (kernel version)
- [ ] cat /etc/issue, /etc/*-release
- [ ] sudo -l
- [ ] cat /etc/passwd, /etc/shadow (if readable)
- [ ] env (environment variables)
- [ ] history
- [ ] ifconfig, ip a
- [ ] netstat -tulpn, ss -tulpn
- [ ] ps aux
- [ ] dpkg -l, rpm -qa
- [ ] find / -perm -4000 2>/dev/null (SUID)
- [ ] find / -perm -2000 2>/dev/null (SGID)
- [ ] getcap -r / 2>/dev/null (capabilities)
- [ ] cat /etc/crontab, ls -la /etc/cron*
- [ ] ls -la /etc/sudoers, /etc/sudoers.d/

### Automated Enumeration
- [ ] LinPEAS
- [ ] LinEnum
- [ ] linux-exploit-suggester
- [ ] linux-exploit-suggester-2
- [ ] pspy (process snooping)

### Kernel Exploits
- [ ] Identify kernel version
- [ ] DirtyCow (CVE-2016-5195)
- [ ] DirtyPipe (CVE-2022-0847)
- [ ] Kernel exploit research
- [ ] linux-exploit-suggester

### SUID/SGID Exploitation
- [ ] Find SUID binaries
- [ ] GTFOBins reference
- [ ] Custom SUID exploitation
- [ ] PATH hijacking with SUID
- [ ] Shared library injection

### Sudo Exploitation
- [ ] sudo -l enumeration
- [ ] GTFOBins sudo section
- [ ] Sudo version exploits
- [ ] LD_PRELOAD exploitation
- [ ] Sudoers misconfigurations

### Cron Job Exploitation
- [ ] Writable cron scripts
- [ ] PATH exploitation in cron
- [ ] Wildcard injection
- [ ] Cron file overwrite

### Capabilities Exploitation
- [ ] cap_setuid
- [ ] cap_setgid
- [ ] cap_dac_override
- [ ] cap_net_bind_service
- [ ] GTFOBins capabilities

### NFS Exploitation
- [ ] showmount -e target
- [ ] no_root_squash exploitation
- [ ] SUID file creation

### Docker Exploitation
- [ ] Docker group membership
- [ ] Docker socket access
- [ ] Container escape
- [ ] Privileged container abuse

### Other Techniques
- [ ] Writable /etc/passwd
- [ ] SSH key injection
- [ ] .bashrc/.profile modification
- [ ] LD_LIBRARY_PATH hijacking
- [ ] Python library hijacking
- [ ] Weak file permissions


## 9.2 Windows Privilege Escalation

### Enumeration
- [ ] whoami /all
- [ ] whoami /priv
- [ ] whoami /groups
- [ ] net user
- [ ] net user <username>
- [ ] net localgroup administrators
- [ ] systeminfo
- [ ] hostname
- [ ] ipconfig /all
- [ ] netstat -ano
- [ ] tasklist /v
- [ ] wmic product get name,version
- [ ] sc query
- [ ] wmic service list full

### Automated Enumeration
- [ ] WinPEAS
- [ ] PowerUp.ps1
- [ ] Seatbelt
- [ ] SharpUp
- [ ] JAWS
- [ ] windows-exploit-suggester (local)
- [ ] wesng (Windows Exploit Suggester NG)

### Token/Privilege Abuse

#### SeImpersonatePrivilege
- [ ] JuicyPotato
- [ ] PrintSpoofer
- [ ] RoguePotato
- [ ] SweetPotato
- [ ] GodPotato

#### SeBackupPrivilege
- [ ] SAM/SYSTEM extraction
- [ ] NTDS.dit extraction
- [ ] Arbitrary file read

#### SeRestorePrivilege
- [ ] Arbitrary file write
- [ ] Service binary replacement

#### SeTakeOwnershipPrivilege
- [ ] Taking ownership of files
- [ ] Registry manipulation

#### SeDebugPrivilege
- [ ] LSASS memory dump
- [ ] Process injection

### Service Exploitation

#### Unquoted Service Paths
- [ ] Identify unquoted paths
- [ ] wmic service get name,displayname,pathname,startmode
- [ ] Place malicious executable

#### Weak Service Permissions
- [ ] accesschk.exe enumeration
- [ ] Modify service binary path
- [ ] sc config manipulation

#### Weak Service Binary Permissions
- [ ] Replace service executable
- [ ] DLL hijacking in services

#### Insecure Service Registry
- [ ] Registry permission check
- [ ] Modify ImagePath

### Registry Exploitation
- [ ] AlwaysInstallElevated
- [ ] AutoRun programs
- [ ] Stored credentials in registry

### Scheduled Tasks
- [ ] schtasks /query
- [ ] Writable task scripts
- [ ] Task creation (if allowed)

### DLL Hijacking
- [ ] Missing DLL identification
- [ ] Writable PATH directories
- [ ] DLL search order abuse
- [ ] Application DLL hijacking

### Credential Harvesting
- [ ] SAM/SYSTEM extraction
- [ ] Mimikatz sekurlsa::logonpasswords
- [ ] LSASS dump
- [ ] cmdkey /list
- [ ] Saved RDP credentials
- [ ] Browser credentials
- [ ] WiFi passwords
- [ ] Credential Manager
- [ ] Unattended installation files
- [ ] Configuration files

### UAC Bypass
- [ ] UAC levels understanding
- [ ] fodhelper.exe bypass
- [ ] eventvwr.exe bypass
- [ ] UACME tool
- [ ] Environment variable bypass

### Kernel Exploits
- [ ] Identify Windows version
- [ ] MS16-032
- [ ] MS15-051
- [ ] MS14-058
- [ ] windows-exploit-suggester


## 9.3 Persistence

### Linux Persistence
- [ ] SSH authorized_keys
- [ ] Cron jobs
- [ ] Systemd services
- [ ] .bashrc/.profile backdoors
- [ ] SUID binary backdoor
- [ ] Kernel module backdoor
- [ ] Init scripts
- [ ] LD_PRELOAD backdoor
- [ ] Web shell

### Windows Persistence
- [ ] Registry Run keys (HKCU/HKLM)
- [ ] Startup folder
- [ ] Scheduled tasks
- [ ] Services
- [ ] DLL hijacking
- [ ] WMI subscriptions
- [ ] Winlogon keys
- [ ] COM hijacking
- [ ] Active Directory persistence
- [ ] Golden ticket
- [ ] Silver ticket
- [ ] Skeleton key


## 9.4 Data Exfiltration

### Data Discovery
- [ ] Sensitive file search
- [ ] Password files
- [ ] Configuration files
- [ ] Database files
- [ ] Private keys
- [ ] Business documents

### Exfiltration Methods
- [ ] HTTP/HTTPS
- [ ] FTP/SFTP
- [ ] SMB
- [ ] DNS exfiltration
- [ ] ICMP tunneling
- [ ] Email
- [ ] Cloud storage
- [ ] Steganography


## 9.5 Covering Tracks

### Log Manipulation
- [ ] Windows Event Log clearing
- [ ] Linux log clearing (/var/log)
- [ ] Application log tampering
- [ ] Selective log deletion

### Artifact Removal
- [ ] Remove tools/binaries
- [ ] Clear command history
- [ ] Remove temporary files
- [ ] Timestomping
- [ ] Restore modified configurations


# ══════════════════════════════════════════════════════════════
#                 PHASE 10: SPECIALIZED TESTING
# ══════════════════════════════════════════════════════════════


## 10.1 Mobile Application Testing

### Android Testing

#### Setup
- [ ] Android Studio/SDK
- [ ] ADB (Android Debug Bridge)
- [ ] Emulator or rooted device
- [ ] Genymotion
- [ ] Frida setup

#### Static Analysis
- [ ] APK extraction
- [ ] APKTool for decompilation
- [ ] JADX for Java code review
- [ ] AndroidManifest.xml analysis
- [ ] Exported components
- [ ] Permissions analysis
- [ ] Hardcoded secrets
- [ ] API keys in code
- [ ] URL endpoints
- [ ] Certificate pinning detection

#### Dynamic Analysis
- [ ] SSL/TLS traffic interception
- [ ] Burp Suite with proxy
- [ ] SSL pinning bypass
- [ ] Frida basics
- [ ] Objection framework
- [ ] Root detection bypass
- [ ] Runtime manipulation
- [ ] Hooking functions

#### Data Storage
- [ ] SharedPreferences
- [ ] SQLite databases
- [ ] Internal/External storage
- [ ] Keystore
- [ ] Backup analysis

#### OWASP Mobile Top 10
- [ ] M1: Improper Platform Usage
- [ ] M2: Insecure Data Storage
- [ ] M3: Insecure Communication
- [ ] M4: Insecure Authentication
- [ ] M5: Insufficient Cryptography
- [ ] M6: Insecure Authorization
- [ ] M7: Client Code Quality
- [ ] M8: Code Tampering
- [ ] M9: Reverse Engineering
- [ ] M10: Extraneous Functionality

#### Android Tools
- [ ] MobSF (automated)
- [ ] Drozer
- [ ] Frida
- [ ] Objection
- [ ] APKTool
- [ ] JADX
- [ ] dex2jar
- [ ] JD-GUI


### iOS Testing

#### Setup
- [ ] macOS (required for some tools)
- [ ] Jailbroken device (preferred)
- [ ] Frida setup
- [ ] Objection

#### Static Analysis
- [ ] IPA extraction
- [ ] Binary analysis
- [ ] Info.plist review
- [ ] Entitlements check
- [ ] Hardcoded secrets
- [ ] URL schemes

#### Dynamic Analysis
- [ ] SSL pinning bypass
- [ ] Keychain access
- [ ] Runtime manipulation
- [ ] Jailbreak detection bypass

#### iOS Tools
- [ ] Frida
- [ ] Objection
- [ ] Hopper/Ghidra
- [ ] MobSF
- [ ] class-dump


## 10.2 Cloud Security Testing

### AWS Security

#### Enumeration
- [ ] S3 bucket enumeration
- [ ] IAM user/role enumeration
- [ ] EC2 instance enumeration
- [ ] Lambda function enumeration
- [ ] RDS database enumeration
- [ ] Secrets Manager enumeration

#### Common Misconfigurations
- [ ] Public S3 buckets
- [ ] Overly permissive IAM policies
- [ ] EC2 metadata SSRF (169.254.169.254)
- [ ] Exposed access keys
- [ ] Unencrypted data storage
- [ ] Open security groups
- [ ] Public RDS instances
- [ ] Lambda with excessive permissions

#### Privilege Escalation
- [ ] IAM policy abuse
- [ ] Role chaining
- [ ] Lambda execution role abuse
- [ ] PassRole exploitation
- [ ] STS AssumeRole abuse

#### AWS Tools
- [ ] aws-cli
- [ ] Pacu (exploitation framework)
- [ ] ScoutSuite
- [ ] Prowler
- [ ] CloudMapper
- [ ] enumerate-iam
- [ ] S3Scanner
- [ ] Trufflehog


### Azure Security

#### Enumeration
- [ ] Azure AD enumeration
- [ ] Blob storage enumeration
- [ ] Virtual machine enumeration
- [ ] Azure functions
- [ ] Key Vault access

#### Common Misconfigurations
- [ ] Public blob containers
- [ ] Managed identity abuse
- [ ] OAuth misconfiguration
- [ ] Exposed storage account keys
- [ ] Open NSGs

#### Azure Tools
- [ ] az-cli
- [ ] AzureHound
- [ ] ROADtools
- [ ] MicroBurst
- [ ] Stormspotter
- [ ] PowerZure


### GCP Security

#### Enumeration
- [ ] Project enumeration
- [ ] Storage bucket enumeration
- [ ] Compute instance enumeration
- [ ] IAM policy review

#### Common Misconfigurations
- [ ] Public storage buckets
- [ ] Service account key exposure
- [ ] Metadata API abuse
- [ ] Over-permissive IAM

#### GCP Tools
- [ ] gcloud cli
- [ ] ScoutSuite
- [ ] GCPBucketBrute


## 10.3 Container Security

### Docker Security
- [ ] Docker daemon misconfiguration
- [ ] Container escape techniques
- [ ] Privileged container abuse
- [ ] Docker socket exposure
- [ ] Image vulnerabilities
- [ ] Secrets in images
- [ ] Capabilities abuse

### Docker Tools
- [ ] docker-bench-security
- [ ] Trivy
- [ ] Clair
- [ ] Dive
- [ ] Anchore

### Kubernetes Security
- [ ] API server access
- [ ] RBAC misconfigurations
- [ ] Pod security policies
- [ ] Service account token abuse
- [ ] etcd access
- [ ] Container escape

### Kubernetes Tools
- [ ] kubectl
- [ ] kube-hunter
- [ ] kube-bench
- [ ] Trivy


## 10.4 IoT Security Testing

### Firmware Analysis
- [ ] Firmware extraction
- [ ] Binwalk analysis
- [ ] File system extraction
- [ ] Hardcoded credentials
- [ ] Encryption key extraction
- [ ] Binary analysis

### Hardware Attacks
- [ ] UART interface
- [ ] JTAG interface
- [ ] SPI flash extraction
- [ ] I2C communication
- [ ] Debug ports

### Network Analysis
- [ ] Protocol identification
- [ ] Traffic analysis
- [ ] Command injection
- [ ] Authentication bypass

### IoT Tools
- [ ] Binwalk
- [ ] Firmwalker
- [ ] Firmware-mod-kit
- [ ] EMBA
- [ ] Ghidra


## 10.5 Thick Client Testing

### Analysis Areas
- [ ] Memory analysis
- [ ] Traffic analysis
- [ ] Local storage
- [ ] Binary analysis
- [ ] DLL analysis

### Common Vulnerabilities
- [ ] Hardcoded credentials
- [ ] Insecure data storage
- [ ] DLL hijacking
- [ ] Unencrypted communication
- [ ] Improper input validation

### Thick Client Tools
- [ ] Process Monitor
- [ ] Process Explorer
- [ ] x64dbg/x32dbg
- [ ] dnSpy (.NET)
- [ ] IDA Pro/Ghidra
- [ ] Wireshark
- [ ] Echo Mirage


# ══════════════════════════════════════════════════════════════
#                      PHASE 11: REPORTING
# ══════════════════════════════════════════════════════════════


## 11.1 Report Structure

### Executive Summary
- [ ] High-level overview of assessment
- [ ] Scope of testing
- [ ] Testing timeline
- [ ] Key findings summary (Critical/High)
- [ ] Overall risk rating
- [ ] Strategic recommendations
- [ ] Business impact summary

### Scope and Methodology
- [ ] Detailed scope definition
- [ ] In-scope assets (IPs, URLs, applications)
- [ ] Out-of-scope items
- [ ] Testing type (Black/Grey/White box)
- [ ] Methodology followed (OWASP, PTES, etc.)
- [ ] Tools used
- [ ] Testing dates and duration
- [ ] Tester information
- [ ] Limitations and constraints

### Findings Overview
- [ ] Vulnerability count by severity
- [ ] Risk distribution chart/graph
- [ ] Critical findings highlight
- [ ] Trend analysis (if repeat assessment)


## 11.2 Detailed Findings

### For Each Vulnerability Include:
- [ ] Unique identifier (e.g., VULN-001)
- [ ] Title (clear and descriptive)
- [ ] Severity rating (Critical/High/Medium/Low/Info)
- [ ] CVSS score and vector
- [ ] Affected asset(s)
- [ ] Vulnerability description
- [ ] Technical details
- [ ] Steps to reproduce (clear, numbered)
- [ ] Proof of Concept (screenshots, code)
- [ ] Impact analysis
- [ ] Remediation recommendation
- [ ] References (CVE, CWE, OWASP)
- [ ] Verification steps (for re-testing)


## 11.3 Severity Rating System

### Critical (CVSS 9.0-10.0)
- [ ] Remote Code Execution
- [ ] SQL Injection with data breach
- [ ] Authentication bypass to admin
- [ ] Privilege escalation to root/SYSTEM
- [ ] Complete system compromise

### High (CVSS 7.0-8.9)
- [ ] SQL Injection (limited)
- [ ] Stored XSS in critical areas
- [ ] Privilege escalation (user to admin)
- [ ] SSRF with internal access
- [ ] Authentication bypass

### Medium (CVSS 4.0-6.9)
- [ ] Reflected XSS
- [ ] CSRF
- [ ] Information disclosure (sensitive)
- [ ] Session management issues
- [ ] Missing security headers

### Low (CVSS 0.1-3.9)
- [ ] Information disclosure (minor)
- [ ] Verbose error messages
- [ ] Cookie without secure flag
- [ ] Internal IP disclosure

### Informational (CVSS 0.0)
- [ ] Best practice recommendations
- [ ] Security improvements
- [ ] Defense in depth suggestions


## 11.4 Remediation Guidance

### For Each Finding
- [ ] Clear remediation steps
- [ ] Priority level
- [ ] Estimated effort
- [ ] Code examples (if applicable)
- [ ] Configuration examples
- [ ] Reference documentation
- [ ] Short-term vs long-term fixes


## 11.5 Appendix

### Supporting Information
- [ ] Raw tool outputs
- [ ] Additional screenshots
- [ ] Technical evidence
- [ ] Network diagrams
- [ ] Full scan results
- [ ] Wordlists used
- [ ] Custom scripts developed


## 11.6 Report Quality Checklist

### Content Quality
- [ ] All findings are accurate
- [ ] Steps to reproduce are clear
- [ ] Screenshots are clear and annotated
- [ ] Sensitive data is redacted
- [ ] No false positives included
- [ ] Impact is clearly explained
- [ ] Remediation is actionable

### Professional Quality
- [ ] Consistent formatting
- [ ] No spelling/grammar errors
- [ ] Professional language
- [ ] Clear and concise writing
- [ ] Proper document structure
- [ ] Page numbers and headers
- [ ] Version control
- [ ] Confidentiality notice


## 11.7 Reporting Tools

### Report Generation
- [ ] Pwndoc
- [ ] Dradis
- [ ] Serpico
- [ ] PlexTrac
- [ ] Ghostwriter
- [ ] AttackForge

### Documentation
- [ ] Microsoft Word
- [ ] Google Docs
- [ ] LaTeX
- [ ] Markdown to PDF

### Evidence Collection
- [ ] Screenshots (Flameshot, Greenshot)
- [ ] Screen recording
- [ ] Request/Response logging
- [ ] Burp Suite export


# ══════════════════════════════════════════════════════════════
#                 PHASE 12: CERTIFICATIONS
# ══════════════════════════════════════════════════════════════


## 12.1 Beginner Certifications

### eJPT (eLearnSecurity Junior Penetration Tester)
- [ ] Networking basics
- [ ] Web application basics
- [ ] Information gathering
- [ ] Vulnerability assessment
- [ ] Basic exploitation
- [ ] Report writing

### CompTIA Security+
- [ ] Security concepts
- [ ] Threats and vulnerabilities
- [ ] Security architecture
- [ ] Operations and incident response
- [ ] Governance and compliance

### CEH (Certified Ethical Hacker)
- [ ] Ethical hacking phases
- [ ] Footprinting and reconnaissance
- [ ] Scanning networks
- [ ] Enumeration
- [ ] System hacking
- [ ] Malware threats
- [ ] Sniffing
- [ ] Social engineering
- [ ] Web server/application hacking
- [ ] SQL injection
- [ ] Cryptography


## 12.2 Intermediate Certifications

### PNPT (Practical Network Penetration Tester)
- [ ] Networking fundamentals
- [ ] Linux
- [ ] Python
- [ ] External network penetration testing
- [ ] Active Directory attacks
- [ ] Web application testing
- [ ] Report writing

### eCPPT (eLearnSecurity Certified Professional Penetration Tester)
- [ ] System security
- [ ] Network security
- [ ] PowerShell
- [ ] Web application security
- [ ] Post-exploitation

### CompTIA PenTest+
- [ ] Planning and scoping
- [ ] Information gathering
- [ ] Vulnerability scanning
- [ ] Attacks and exploits
- [ ] Post-exploitation
- [ ] Reporting


## 12.3 Advanced Certifications

### OSCP (Offensive Security Certified Professional)
- [ ] Information gathering
- [ ] Vulnerability scanning
- [ ] Web application attacks
- [ ] Buffer overflows (Windows & Linux)
- [ ] Client-side attacks
- [ ] Working with exploits
- [ ] Privilege escalation
- [ ] Active Directory attacks
- [ ] Post-exploitation
- [ ] Report writing
- [ ] 24-hour practical exam

### CRTP (Certified Red Team Professional)
- [ ] Active Directory enumeration
- [ ] Local privilege escalation
- [ ] Domain privilege escalation
- [ ] Kerberos attacks
- [ ] Cross-trust attacks
- [ ] Persistence techniques
- [ ] Evasion techniques

### OSWE (Offensive Security Web Expert)
- [ ] White box web application testing
- [ ] Source code analysis
- [ ] Authentication bypass
- [ ] Injection attacks
- [ ] Type juggling
- [ ] SQL injection (advanced)
- [ ] Deserialization attacks


## 12.4 Expert Certifications

### OSEP (Offensive Security Experienced Penetration Tester)
- [ ] Antivirus evasion
- [ ] Application whitelisting bypass
- [ ] Advanced lateral movement
- [ ] Process injection
- [ ] Custom payload development

### OSED (Offensive Security Exploit Developer)
- [ ] x86 assembly
- [ ] Buffer overflows
- [ ] SEH exploitation
- [ ] Shellcode development
- [ ] DEP/ASLR bypass
- [ ] Egg hunters
- [ ] ROP chains

### OSCE3 (OSEP + OSWE + OSED)
- [ ] Complete all three certifications


## 12.5 Recommended Certification Path

### Path 1: Network-Focused
- [ ] eJPT → PNPT → OSCP → CRTP → OSEP

### Path 2: Web-Focused
- [ ] eJPT → PNPT → OSCP → OSWE

### Path 3: Red Team
- [ ] eJPT → PNPT → OSCP → CRTP → CRTE → OSEP


# ══════════════════════════════════════════════════════════════
#                    PRACTICE PLATFORMS
# ══════════════════════════════════════════════════════════════


## Free Platforms
- [ ] TryHackMe (free tier)
- [ ] HackTheBox (free tier)
- [ ] VulnHub
- [ ] PortSwigger Web Security Academy (100% free)
- [ ] OWASP WebGoat
- [ ] OWASP Juice Shop
- [ ] PentesterLab (free exercises)
- [ ] Damn Vulnerable Web Application (DVWA)
- [ ] bWAPP
- [ ] Metasploitable
- [ ] Kioptrix series
- [ ] HackThisSite
- [ ] Root Me
- [ ] CyberDefenders (DFIR)

## Paid Platforms
- [ ] TryHackMe Premium
- [ ] HackTheBox VIP
- [ ] HackTheBox Academy
- [ ] PentesterLab Pro
- [ ] Offensive Security PG Practice
- [ ] Cybrary
- [ ] INE/eLearnSecurity


# ══════════════════════════════════════════════════════════════
#                     ESSENTIAL RESOURCES
# ══════════════════════════════════════════════════════════════


## Cheat Sheets & References
- [ ] GTFOBins (Linux privilege escalation)
- [ ] LOLBAS (Windows living off the land)
- [ ] HackTricks (book.hacktricks.xyz)
- [ ] PayloadsAllTheThings (GitHub)
- [ ] OWASP Cheat Sheet Series
- [ ] RevShells (revshells.com)
- [ ] CyberChef

## Wordlists
- [ ] SecLists
- [ ] rockyou.txt
- [ ] FuzzDB
- [ ] Dirbuster wordlists
- [ ] Common-Credentials

## Books
- [ ] The Web Application Hacker's Handbook
- [ ] Penetration Testing by Georgia Weidman
- [ ] Red Team Field Manual (RTFM)
- [ ] The Hacker Playbook series
- [ ] Black Hat Python

## YouTube Channels
- [ ] IppSec (HackTheBox walkthroughs)
- [ ] John Hammond
- [ ] LiveOverflow
- [ ] NetworkChuck
- [ ] The Cyber Mentor
- [ ] David Bombal
- [ ] STÖK

## Blogs & Websites
- [ ] PortSwigger Research Blog
- [ ] Pentester Land
- [ ] Hackerone Hacktivity
- [ ] Bug Bounty Writeups
- [ ] 0xdf hacks stuff


# ══════════════════════════════════════════════════════════════
#                      PROGRESS TRACKER
# ══════════════════════════════════════════════════════════════


## Phase Completion Status

| Phase | Status | Percentage |
|-------|--------|------------|
| Phase 1: Prerequisites | [ ] | ___% |
| Phase 2: Core Concepts | [ ] | ___% |
| Phase 3: Information Gathering | [ ] | ___% |
| Phase 4: Scanning & Enumeration | [ ] | ___% |
| Phase 5: Vulnerability Assessment | [ ] | ___% |
| Phase 6: Exploitation | [ ] | ___% |
| Phase 7: Web Application Testing | [ ] | ___% |
| Phase 8: Network Penetration Testing | [ ] | ___% |
| Phase 9: Post Exploitation | [ ] | ___% |
| Phase 10: Specialized Testing | [ ] | ___% |
| Phase 11: Reporting | [ ] | ___% |
| Phase 12: Certifications | [ ] | ___% |


## Monthly Goals

### Month: ___________
- [ ] Goal 1: 
- [ ] Goal 2:
- [ ] Goal 3:
- [ ] Goal 4:


## Notes & Observations

_________________________________
_________________________________
_________________________________
_________________________________
_________________________________


# ══════════════════════════════════════════════════════════════
#                       END OF CHECKLIST
# ══════════════════════════════════════════════════════════════