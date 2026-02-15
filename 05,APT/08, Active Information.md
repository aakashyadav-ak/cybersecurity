##  Active Information Gathering 
Actively interact with the target to discover:
- DNS records
- subdomains
- live hosts
- open ports
- running services

> ⚠️ Active recon is detectable (logs get generated).

---

##  Domain Name System (DNS) Enumerations

### What to find
- A record (IP)
- AAAA record (IPv6)
- NS (Name servers)
- MX (Mail servers)
- TXT (SPF, DKIM, verification)
- CNAME (aliases)
- SOA (DNS authority)

| Record | Purpose | Example | Pentesting Value |
| :--- | :--- | :--- | :--- |
| `A` | IPv4 address | example.com → 192.168.1.10 | Target identification |
| `AAAA` | IPv6 address | example.com → 2001:db8::1 | IPv6 targets |
| `CNAME` | Canonical name (alias) | www → example.com | Find relationships |
| `MX` | Mail servers | mail.example.com | Email infrastructure |
| `NS` | Name servers | ns1.example.com | DNS servers |
| `TXT` | Text records | SPF, DKIM, verification | Info disclosure |
| `SOA` | Start of Authority | Primary DNS, admin email | DNS admin info |
| `PTR` | Reverse DNS | 192.168.1.10 → server.example.com | Hostname discovery |
| `SRV` | Service records | _ldap._tcp.dc | Service discovery |

### 🛠 Tools / Commands
```bash
nslookup example.com
dig example.com
dig A example.com
dig NS example.com
dig MX example.com
dig TXT example.com
host example.com

```


##  Automating Lookups
Manual DNS checks are slow. Automation helps to:
- brute-force subdomains
- quickly collect DNS records
- save output for reporting

 Tools
- dig + bash loops
- dnsrecon
- sublist3r (mostly passive but still useful)

Example: brute subdomains using wordlist

```bash
for sub in $(cat wordlist.txt); do
  host $sub.example.com
done
```

**Using dnsrecon**


```bash
dnsrecon -d example.com
dnsrecon -d example.com -t brt -D wordlist.txt
```




## NMAP and Masscan

### Nmap (accurate, slower)
**Used for:**
- service detection
- OS detection
- scripts (NSE)
- version scanning

**Common commands:**
```bash
nmap -sn 192.168.1.0/24
nmap -sS -p- 192.168.1.10
nmap -sV -p 80,443,22 192.168.1.10
nmap -A 192.168.1.10
```


### Masscan (very fast, less accurate)
**Used for:**
- large network scanning
- quickly finding open ports

**Example:**
```bash
sudo masscan 192.168.1.0/24 -p1-65535 --rate 10000
```


## Port Enumeration
l
**Find:**
- open ports
- services running
- versions
- possible vulnerabilities







