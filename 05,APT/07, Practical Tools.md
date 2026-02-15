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