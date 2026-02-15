Collect information about the target **without directly interacting** with their servers.

- Less chance of detection  
- Useful before scanning/exploitation  
- Mostly done using public sources (OSINT)


## Website Reconnaissance
**Collect info:**
- Domain details
- IP address (if possible)
- Technologies used (CMS, frameworks, server)
- Subdomains
- Hidden directories / endpoints (from public sources)
- Public files (PDF, docs, images metadata)
- Robots.txt / sitemap.xml (sometimes passive, sometimes semi-active)

### 1.  WHOIS Lookup
```bash
# Command-line WHOIS
whois example.com

# Online tools
- who.is
- whois.domaintools.com
```
**Information Gathered:**
- Domain registrar
- Registration/expiration dates
- Name servers
- Registrant contact info (if not privacy-protected)

### 2, DNS Enumeration
```bash
# Basic DNS queries
nslookup example.com
dig example.com ANY
host -a example.com

# DNS record types
dig example.com A      # IPv4 address
dig example.com AAAA   # IPv6 address
dig example.com MX     # Mail servers
dig example.com NS     # Name servers
dig example.com TXT    # Text records
dig example.com SOA    # Start of Authority
```

###  3. Subdomain Enumeration
```bash
# Using Sublist3r
sublist3r -d example.com

# Using Amass
amass enum -d example.com

# Using DNSdumpster (web-based)
https://dnsdumpster.com

# Using crt.sh (Certificate Transparency)
https://crt.sh/?q=%25.example.com
```

### 4. Wayback Machine
```
# Archive.org
https://web.archive.org

Use cases:
- View old versions of websites
- Find removed/hidden pages
- Discover old vulnerabilities
- Locate forgotten admin panels
```

### 5.Google dorks:
```
site:example.com
site:example.com login
site:example.com admin
site:example.com ext:pdf OR ext:doc OR ext:xls
site:example.com inurl:backup
site:example.com inurl:config
```
___

# Netcraft, Shodan, Email Harvesting

## Netcraft (Passive Domain Recon)

**Used to find:**
- hosting provider
- technologies
- SSL details
- server history
```
URL: https://sitereport.netcraft.com

Information Provided:
- Site technology
- Hosting history
- SSL/TLS certificate info
- Site rank and traffic
- Associated domains
```

## hodan (Search engine for public devices)

**Used to find:**
- open ports on public IP
- service banners
- exposed services (RDP/SSH/DB/etc.)
- potential CVE hints


```
URL: https://shodan.io

Basic Searches:
- hostname:example.com
- net:192.168.1.0/24
- port:22
- apache
- country:US
- city:"New York"
```


## Email Harvesting

**Used to collect:**
- employee emails
- email patterns
- leaked emails (if allowed)

**Tools:**
- theHarvester
- hunter.io
- phonebook.cz

###  theHarvester
```bash
# Basic usage
theharvester -d example.com -b all

# Specific sources
theharvester -d example.com -b google,linkedin,bing

# Limit results
theharvester -d example.com -b google -l 200

# Save results
theharvester -d example.com -b all -f output.html
```


___
# Open Source Intelligence (OSINT) Framework
A categorized collection of OSINT resources used for:
- domains
- subdomains
- usernames
- emails
- leaked credentials
- social media footprint
- public infrastructure data

## OSINT Tools
### Maltego
- Visual link analysis
- Entity relationships
- Automated transforms
- Community Edition available

### Recon-ng
```
# Launch
recon-ng

# Create workspace
workspaces create company_name

# Load module
modules load recon/domains-hosts/google_site_web

# Set options
options set SOURCE example.com

# Run
run

# Show results
show hosts
```


### Google Dorking
```
# Find subdomains
site:example.com

# Find specific file types
site:example.com filetype:pdf

# Find login pages
site:example.com inurl:login

# Find directory listings
intitle:"index of" site:example.com

# Find exposed documents
site:example.com ext:doc | ext:docx | ext:xls

# Find vulnerable pages
site:example.com inurl:admin
```

### Social Media OSINT
#### LinkedIn Reconnaissance