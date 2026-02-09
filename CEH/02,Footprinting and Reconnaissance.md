# Module 2: Footprinting and Reconnaissance

---

## 1. Footprinting Concepts

### What is Footprinting?
Footprinting is the **first phase** of ethical hacking where an attacker collects information about a target system, network, or organization before attempting an attack.

```
┌─────────────────────────────────────────────────────────────┐
│                 FOOTPRINTING METHODOLOGY                     │
├─────────────────────────────────────────────────────────────┤
│  1. Define Scope → 2. Gather Info → 3. Analyze Data         │
│                           ↓                                  │
│  4. Create Report → 5. Identify Vulnerabilities              │
└─────────────────────────────────────────────────────────────┘
```
### Objectives of Footprinting
- Collect network information (domain names, IP addresses, protocols)
- Collect system information (usernames, system banners, OS details)
- Collect organization information (employee details, locations, phone numbers)

### Types of Footprinting

| Type | Description |
|------|-------------|
| **Passive Footprinting** | Gathering information without direct interaction with the target |
| **Active Footprinting** | Gathering information by directly interacting with the target |

### Passive Footprinting Techniques
- Searching through search engines
- Finding information through social media
- Gathering competitive intelligence
- WHOIS lookup
- Using web archives (Wayback Machine)
- Job postings analysis
- Google dorks

### Active Footprinting Techniques
- Querying DNS servers
- Traceroute analysis
- Social engineering
- Email tracking
- Extracting website metadata
- Network scanning

### Information Gathered During Footprinting

**Organization Information:**
- Employee details
- Telephone numbers
- Branch locations
- Company background
- Web technologies
- News articles

**Network Information:**
- Domain names
- Network blocks
- IP addresses
- Network topology
- Trusted routers
- Firewall details
- Network protocols
- VPN points

**System Information:**
- Web server OS
- Server locations
- Publicly available email addresses
- Usernames and passwords

---

## 2. Footprinting Through Search Engines

### Google Hacking / Google Dorks
Google Dorking uses advanced search operators to find sensitive information indexed by Google.

### Common Google Dork Operators

| Operator | Description | Example |
|----------|-------------|---------|
| site: | Restricts results to specific domain | site:example.com |
| intitle: | Searches for keywords in page title | intitle:admin login |
| inurl: | Searches for keywords in URL | inurl:admin.php |
| filetype: | Searches for specific file types | filetype:pdf confidential |
| intext: | Searches for keywords in page body | intext:password |
| cache: | Shows cached version of page | cache:example.com |
| link: | Finds pages linking to a URL | link:example.com |
| related: | Finds similar websites | related:example.com |
| info: | Shows information about a URL | info:example.com |
| allintitle: | All words must be in title | allintitle:admin panel |
| allinurl: | All words must be in URL | allinurl:login admin |

### Advanced Google Dork Examples

site:target.com inurl:login OR inurl:admin
site:target.com filetype:pdf OR filetype:doc OR filetype:xlsx
site:target.com filetype:conf OR filetype:cfg OR filetype:env
site:target.com filetype:sql OR filetype:db
site:target.com filetype:bak OR filetype:backup
intitle:"index of" "parent directory"
filetype:log intext:password
site:target.com inurl:wp-admin
inurl:phpmyadmin intitle:phpMyAdmin
inurl:view/view.shtml
intitle:"Live View / - AXIS"

### Google Hacking Database (GHDB)
- Maintained by Offensive Security
- URL: https://www.exploit-db.com/google-hacking-database
- Categories: Footholds, Files containing usernames, Sensitive directories, Web server detection, Vulnerable files, Error messages, Passwords

### Other Search Engines for Footprinting

| Search Engine | Purpose |
|---------------|---------|
| Shodan | Search engine for Internet-connected devices |
| Censys | Search engine for devices and certificates |
| ZoomEye | Cyberspace search engine |
| FOCA | Metadata extraction tool |
| theHarvester | Email and domain reconnaissance |

### Shodan Search Filters

apache
port:22
country:US
city:"New York"
org:"Target Company"
vuln:CVE-2021-44228
webcam
product:MySQL
apache port:443 country:US

---

## 3. Footprinting Through Web Services

### People Search Services
- Pipl - Deep web people search
- Spokeo - People search engine
- Intelius - Background check services
- BeenVerified - People search
- PeekYou - Social media aggregator

### Financial Services
- SEC EDGAR - Company filings and reports
- Crunchbase - Company information
- D&B Hoovers - Business intelligence
- Bloomberg - Financial data

### Job Portals (Information Gathering)
- LinkedIn Jobs
- Indeed
- Glassdoor
- Monster

**Job Postings Reveal:**
- Technology stack used
- Security tools implemented
- Network infrastructure details
- Internal projects

### Internet Archive (Wayback Machine)
- URL: https://web.archive.org
- Shows historical snapshots of websites
- Can reveal: Old employee information, Removed content, Previous technology stack, Old vulnerabilities

### IoT Search Engines

| Tool | Description |
|------|-------------|
| Shodan | Search engine for IoT devices |
| Censys | TLS certificates and device search |
| Thingful | IoT search engine |
| FOFA | Cyberspace asset search |

### Other Web Services for Footprinting
- Netcraft - Website technology detection
- BuiltWith - Technology profiler
- Wappalyzer - Technology identification
- Sublist3r - Subdomain enumeration
- crt.sh - Certificate transparency logs
- SecurityTrails - DNS and domain intelligence
- VirusTotal - Domain/IP analysis
- RobTex - Network analysis

---

## 4. Footprinting Through Social Networking Sites

### Popular Platforms for Intelligence Gathering

| Platform | Information Available |
|----------|----------------------|
| LinkedIn | Employee names, job titles, skills, company structure |
| Facebook | Personal info, locations, relationships, events |
| Twitter/X | Opinions, announcements, technologies used |
| Instagram | Photos, locations, lifestyle |
| GitHub | Code, credentials, API keys, internal projects |

### LinkedIn Intelligence Gathering
- Company employee count
- Employee job titles and roles
- Technology skills
- Company hierarchy
- Business connections
- Job postings (technology stack)

### GitHub Reconnaissance

"api_key" OR "apikey" site:github.com target
"AWS_ACCESS_KEY" site:github.com
"BEGIN RSA PRIVATE KEY" site:github.com
filename:config password site:github.com

### GitHub Dorks

org:targetcompany password
org:targetcompany secret
org:targetcompany api_key
org:targetcompany token
org:targetcompany filename:.env
org:targetcompany filename:config.php
org:targetcompany filename:settings.py

### Social Engineering Through Social Media
- Identifying key employees
- Understanding organizational structure
- Finding personal information for pretexting
- Identifying security awareness levels
- Gathering information for phishing attacks

### Tools for Social Media Footprinting

| Tool | Purpose |
|------|---------|
| Sherlock | Username search across platforms |
| Social Searcher | Real-time social mention search |
| Followerwonk | Twitter analytics |
| Hootsuite | Social media monitoring |
| Maltego | Social network mapping |

---

## 5. Website Footprinting

### Website Information Gathering

**Examining Web Page Source Code - Look for:**
- HTML comments with sensitive info
- Hidden form fields
- JavaScript files
- API endpoints
- Developer comments
- Version information

### HTTP Headers Analysis

Using curl to view headers:
curl -I https://target.com

Headers to analyze:
Server: Apache/2.4.41
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319
Set-Cookie: security settings

### Important HTTP Headers

| Header | Information Revealed |
|--------|---------------------|
| Server | Web server software and version |
| X-Powered-By | Backend technology |
| X-AspNet-Version | ASP.NET version |
| X-Generator | CMS information |
| Set-Cookie | Session handling, security flags |

### Website Mirroring Tools

| Tool | Description |
|------|-------------|
| HTTrack | Website copier |
| wget | Command-line downloader |
| WebCopier | Website download tool |
| Octoparse | Web scraping tool |

Mirror website with wget:
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://target.com

Using HTTrack:
httrack "https://target.com" -O /tmp/mirror

### Technology Identification Tools
- Wappalyzer (Browser Extension)
- BuiltWith (Online Service)
- Netcraft (Online Service)
- WhatWeb (Command Line)
- Retire.js (JavaScript Library Detection)

Using WhatWeb:
whatweb target.com

### Website Metadata Extraction

Using exiftool on downloaded files:
exiftool document.pdf

Information extracted:
- Author name
- Software used
- Creation date
- Modification history
- GPS coordinates (images)

### Robots.txt and Sitemap.xml

Check robots.txt:
curl https://target.com/robots.txt

Example robots.txt content:
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/

Check sitemap:
curl https://target.com/sitemap.xml

---

## 6. Email Footprinting

### Email Header Analysis

**Email Headers Reveal:**
- Sender's IP address
- Mail servers used
- Email client/software
- Authentication results
- Routing information

### Important Email Headers

| Header | Information |
|--------|-------------|
| From | Sender's email address |
| Received | Mail servers in the path |
| X-Originating-IP | Sender's IP address |
| Message-ID | Unique message identifier |
| X-Mailer | Email client used |
| Return-Path | Bounce address |
| Authentication-Results | SPF, DKIM, DMARC results |

### Reading Email Headers (Bottom to Top)

Received: from mail.target.com (192.168.1.10)
        by mx.google.com with SMTP;
        Mon, 15 Jan 2024 10:30:00 -0500
Received: from [10.0.0.5] (unknown [203.0.113.50])
        by mail.target.com with ESMTP;
        Mon, 15 Jan 2024 10:29:55 -0500

The bottom "Received" header shows the original sender IP: 203.0.113.50

### Email Tracking Tools

| Tool | Purpose |
|------|---------|
| eMailTrackerPro | Email header analysis |
| Infoga | Email information gathering |
| theHarvester | Email address harvesting |
| Hunter.io | Email finder |
| Email Header Analyzer | Online header analysis |

### Email Harvesting

Using theHarvester:
theHarvester -d target.com -b google,bing,linkedin

Using hunter.io API:
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY"

### Email Verification

Verify email exists using SMTP verification:
telnet mail.target.com 25
HELO test.com
MAIL FROM:<test@test.com>
RCPT TO:<admin@target.com>

250 = exists
550 = doesn't exist

---

## 7. WHOIS Footprinting

### What is WHOIS?
WHOIS is a query/response protocol used to query databases that store registered users of internet resources (domain names, IP address blocks, etc.)

### Information from WHOIS
- Domain name and registration date
- Expiration date
- Registrar information
- Registrant contact (Name, Email, Phone)
- Administrative contact
- Technical contact
- Name servers
- Domain status
- DNSSEC status

### WHOIS Lookup Methods

Command line WHOIS:
whois target.com

For IP address:
whois 192.168.1.1

### Online WHOIS Tools

| Tool | URL |
|------|-----|
| ICANN Lookup | lookup.icann.org |
| Whois.net | whois.net |
| DomainTools | whois.domaintools.com |
| ARIN | whois.arin.net (IP addresses) |
| RIPE | apps.db.ripe.net (Europe) |
| APNIC | wq.apnic.net (Asia-Pacific) |

### Regional Internet Registries (RIRs)

| RIR | Region |
|-----|--------|
| ARIN | North America |
| RIPE NCC | Europe, Middle East, Central Asia |
| APNIC | Asia-Pacific |
| LACNIC | Latin America, Caribbean |
| AFRINIC | Africa |

### Sample WHOIS Output

Domain Name: TARGET.COM
Registry Domain ID: 12345678_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.com
Registrar URL: http://www.registrar.com
Updated Date: 2023-01-15T10:00:00Z
Creation Date: 2000-05-20T04:00:00Z
Registry Expiry Date: 2025-05-20T04:00:00Z
Registrar: Example Registrar, Inc.
Registrant Name: John Doe
Registrant Organization: Target Company
Registrant Email: admin@target.com
Name Server: NS1.TARGET.COM
Name Server: NS2.TARGET.COM
DNSSEC: unsigned

---

## 8. DNS Footprinting

### DNS Record Types

| Record Type | Description |
|-------------|-------------|
| A | Maps hostname to IPv4 address |
| AAAA | Maps hostname to IPv6 address |
| MX | Mail exchange servers |
| NS | Authoritative name servers |
| CNAME | Canonical name (alias) |
| PTR | Reverse DNS lookup |
| SOA | Start of Authority (zone info) |
| TXT | Text records (SPF, DKIM, etc.) |
| SRV | Service location records |
| HINFO | Host information |

### DNS Enumeration Commands

Using nslookup:
nslookup target.com
nslookup -type=MX target.com
nslookup -type=NS target.com
nslookup -type=ANY target.com

Using dig:
dig target.com
dig target.com MX
dig target.com NS
dig target.com ANY
dig target.com AXFR @ns1.target.com

Using host:
host target.com
host -t MX target.com
host -t NS target.com
host -l target.com ns1.target.com

### DNS Zone Transfer

A misconfigured DNS server may allow zone transfers, revealing all DNS records for a domain.

Attempt zone transfer with dig:
dig axfr @ns1.target.com target.com

Using host:
host -l target.com ns1.target.com

Using nslookup:
nslookup
server ns1.target.com
set type=any
ls -d target.com

### DNS Enumeration Tools

| Tool | Description |
|------|-------------|
| DNSrecon | DNS enumeration script |
| DNSenum | DNS enumeration tool |
| Fierce | DNS reconnaissance tool |
| DNSmap | Subdomain brute forcing |
| Sublist3r | Subdomain enumeration |

Using dnsrecon:
dnsrecon -d target.com

Using dnsenum:
dnsenum target.com

Using fierce:
fierce --domain target.com

Using sublist3r:
sublist3r -d target.com

### Subdomain Enumeration

Using Sublist3r:
python sublist3r.py -d target.com

Using Amass:
amass enum -d target.com

Using Subfinder:
subfinder -d target.com

Certificate Transparency logs:
curl "https://crt.sh/?q=%.target.com&output=json" | jq

### DNS Cache Snooping

Check if domain is in cache (non-recursive query):
dig @dns-server.com target.com A +norecurse

---

## 9. Network Footprinting

### Network Range Discovery

Find IP range from WHOIS:
whois -h whois.arin.net "n target.com"

Using ARIN WHOIS:
whois -h whois.arin.net 192.168.1.1

### Traceroute

Traceroute discovers the path packets take to reach the target, revealing intermediate routers and network topology.

Linux/Mac:
traceroute target.com
traceroute -I target.com (ICMP)
traceroute -T target.com (TCP)

Windows:
tracert target.com

Using TCP SYN:
tcptraceroute target.com 80

### Traceroute Analysis

Hop  IP Address        RTT      Description
1    192.168.1.1       1ms      Local gateway
2    10.0.0.1          5ms      ISP router
3    203.0.113.1       15ms     Regional router
4    198.51.100.1      25ms     Backbone router
5    * * *                      Firewall (filtered)
6    93.184.216.34     35ms     Target server

### Network Topology Mapping Tools

| Tool | Description |
|------|-------------|
| Traceroute | Path discovery |
| Visual Traceroute | Graphical path mapping |
| Network Topology Mapper | Network diagramming |
| SolarWinds | Network mapping suite |
| Maltego | Relationship mapping |

### Autonomous System (AS) Information

Find AS number:
whois -h whois.radb.net 192.168.1.1

BGP looking glass - Use online BGP tools like:
- bgp.he.net
- bgpview.io

---

## 10. Footprinting Through Social Engineering

### Social Engineering Definition
The art of manipulating people to divulge confidential information or perform actions that compromise security.

### Types of Social Engineering

| Technique | Description |
|-----------|-------------|
| Phishing | Fake emails/websites |
| Vishing | Voice phishing (phone calls) |
| Smishing | SMS phishing |
| Impersonation | Pretending to be someone else |
| Pretexting | Creating false scenario |
| Baiting | Offering something enticing |
| Quid Pro Quo | Offering help/service |
| Tailgating | Following authorized person |
| Dumpster Diving | Searching through trash |
| Shoulder Surfing | Watching someone's screen |
| Eavesdropping | Listening to conversations |

### Information Gathered via Social Engineering
- Employee names and positions
- Internal phone numbers
- Email addresses
- Organizational hierarchy
- Business processes
- Technology in use
- Security policies
- Physical security details

### Social Engineering for Footprinting Examples

| Technique | Example |
|-----------|---------|
| Phishing | Sending email requesting login credentials |
| Pretexting | Calling IT support as a "new employee" |
| Impersonation | Posing as IT support or vendor |
| Dumpster Diving | Finding discarded documents |

### Pretexting Scenarios

Scenario 1 - IT Support:
"Hi, this is John from IT. We're updating our security systems and need to verify your account details..."

Scenario 2 - Survey:
"We're conducting a company satisfaction survey. Could you tell us what software you use daily?"

Scenario 3 - Job Recruiter:
"I'm recruiting for a similar position. What technologies does your company use?"

---

## 11. Footprinting Tools

### Comprehensive Footprinting Tools

| Tool | Category | Description |
|------|----------|-------------|
| Maltego | OSINT | Visual link analysis and data mining |
| Recon-ng | Web Recon | Web reconnaissance framework |
| theHarvester | Email/Domain | Email and subdomain harvesting |
| Shodan | IoT Search | Internet device search engine |
| FOCA | Metadata | Metadata extraction tool |
| SpiderFoot | OSINT | Automated OSINT collection |
| Metagoofil | Metadata | Document metadata extractor |
| OSRFramework | OSINT | Username and identity research |

### Recon-ng Usage

Start recon-ng:
recon-ng

Create workspace:
workspaces create target_recon

Add domain:
db insert domains target.com

Load modules:
modules search
modules load recon/domains-hosts/hackertarget
run

View results:
show hosts

### theHarvester Usage

Basic usage:
theHarvester -d target.com -b all

Specific sources:
theHarvester -d target.com -b google,bing,linkedin

Save output:
theHarvester -d target.com -b all -f output.html

### Maltego Features
- Domain to DNS names
- DNS names to IP addresses
- Email address extraction
- Social network mapping
- Phone number to location
- Company to people relationships
- Infrastructure mapping
- Visual link analysis

### SpiderFoot Usage

Start SpiderFoot web interface:
spiderfoot -l 127.0.0.1:5001

Command line scan:
spiderfoot -s target.com -t INTERESTING_FILE,DNS

### OSINT Framework Categories
- Username
- Email Address
- Domain Name
- IP Address
- Social Networks
- Instant Messaging
- People Search
- Telephone Numbers
- Public Records
- Business Records
- Geolocation
- Search Engines
- Forums
- Archives
- Documents/Files
- Threat Intelligence
- Dark Web
- Digital Currency

### Additional Tools Summary

| Category | Tools |
|----------|-------|
| DNS | dig, nslookup, DNSrecon, Fierce, DNSenum |
| WHOIS | whois, DomainTools, ARIN lookup |
| Web | WhatWeb, BuiltWith, Wappalyzer, Netcraft |
| Email | Hunter.io, theHarvester, Infoga |
| Social | Sherlock, Maltego, Social-Searcher |
| Network | traceroute, Nmap, Zenmap |
| Metadata | FOCA, Metagoofil, ExifTool |

---

## 12. Footprinting Countermeasures

### Organizational Countermeasures
- Implement security awareness training
- Create and enforce security policies
- Limit information shared on social media
- Use privacy services for domain registration
- Educate employees about social engineering
- Implement proper document disposal
- Restrict job posting technical details
- Monitor for data leaks

### Technical Countermeasures

| Area | Countermeasure |
|------|----------------|
| DNS | Disable zone transfers, Split DNS |
| WHOIS | Use WHOIS privacy protection |
| Web | Remove unnecessary metadata, version info |
| Email | Implement SPF, DKIM, DMARC |
| Network | Block ICMP at perimeter, use IDS/IPS |
| Social | Limit public information exposure |

### DNS Hardening

Disable zone transfers (BIND configuration) in named.conf:
zone "target.com" {
    type master;
    file "target.com.zone";
    allow-transfer { none; };
};

Or limit to specific servers:
allow-transfer { 192.168.1.2; 192.168.1.3; };

### Web Server Hardening

Apache - Hide version:
ServerTokens Prod
ServerSignature Off

Remove X-Powered-By header:
Header unset X-Powered-By

Nginx - Hide version:
server_tokens off;

### Email Security (DNS TXT Records)

SPF Record:
v=spf1 mx a ip4:192.168.1.0/24 -all

DMARC Record:
v=DMARC1; p=reject; rua=mailto:reports@target.com

DKIM - Configured through email server

---

## Quick Reference Card

### Essential Commands

DNS Enumeration:
dig target.com ANY
nslookup -type=ANY target.com
dig axfr @ns1.target.com target.com

WHOIS:
whois target.com
whois 192.168.1.1

Network:
traceroute target.com
tracert target.com (Windows)

Email Harvesting:
theHarvester -d target.com -b all

Subdomain Enumeration:
sublist3r -d target.com
amass enum -d target.com

Web Technology:
whatweb target.com

### Key Google Dorks

site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql | ext:db
site:target.com intext:password

### Important Ports for Footprinting

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 3306 | MySQL |
| 3389 | RDP |

---
### CEH Exam Focus Areas
1. Know the difference between passive and active footprinting
2. Memorize common Google dork operators
3. Understand DNS record types and their purposes
4. Know WHOIS information fields
5. Understand email header analysis
6. Be familiar with major footprinting tools
7. Know countermeasures for each footprinting technique
