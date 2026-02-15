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

### DNS Enumeration
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

###  Subdomain Enumeration
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