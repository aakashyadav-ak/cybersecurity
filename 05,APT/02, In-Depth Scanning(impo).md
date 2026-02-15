# Scan All Top 20 Ports

## Port Ranges:
```
┌────────────────────────────────────────────────────┐
│  0 - 1023      →  Well-Known Ports (System)       │
│  1024 - 49151  →  Registered Ports (User)         │
│  49152 - 65535 →  Dynamic/Private Ports           │
└────────────────────────────────────────────────────┘
Total Ports: 65,535 (TCP) + 65,535 (UDP) = 131,070
```

#### Top 20 Critical Ports

| Port | Service | Protocol | Why Important |
| :--- | :--- | :--- | :--- |
| **21** | FTP | TCP | Anonymous login, credentials |
| **22** | SSH | TCP | Brute force, old versions |
| **23** | Telnet | TCP | Clear text credentials |
| **25** | SMTP | TCP | Email relay, user enum |
| **53** | DNS | TCP/UDP | Zone transfer, cache poisoning |
| **80** | HTTP | TCP | Web vulnerabilities |
| **110** | POP3 | TCP | Email credentials |
| **111** | RPCbind | TCP | NFS enumeration |
| **135** | MSRPC | TCP | Windows RPC attacks |
| **139** | NetBIOS | TCP | SMB legacy attacks |
| **143** | IMAP | TCP | Email credentials |
| **443** | HTTPS | TCP | SSL/TLS issues, web vulns |
| **445** | SMB | TCP | EternalBlue, file shares |
| **993** | IMAPS | TCP | Encrypted IMAP |
| **995** | POP3S | TCP | Encrypted POP3 |
| **1433** | MSSQL | TCP | Database attacks |
| **1521** | Oracle | TCP | Database attacks |
| **3306** | MySQL | TCP | Database attacks |
| **3389** | RDP | TCP | BlueKeep, brute force |
| **5432** | PostgreSQL | TCP | Database attacks |


# Tools
## NMAP

### 1. TCP Connect Scan (Full Connection)
```bash
nmap -sT 192.168.1.1
```

- Completes 3-way handshake
- Logged by target
- Use when: You need accuracy

### 2. SYN Scan (Stealth/Half-Open) 
```bash
nmap -sS 192.168.1.1
```

- Sends SYN, receives SYN/ACK, sends RST
- Faster, less logged
- Requires root privileges

### 3. UDP Scan
```bash
nmap -sU 192.168.1.1
```
- Slower than TCP
- Important for DNS, SNMP, DHCP

### 4. Version Detection
```bash
nmap -sV 192.168.1.1
```
- Identifies service versions
- Critical for finding vulnerable versions
### 5. OS Detection
```bash
nmap -O 192.168.1.1
```
- Identifies operating system
- Helps in exploit selection


## Important commands

**Full Scan - All 65535 Ports**
```
nmap -p- 192.168.1.1
```

**Specific Ports**
```Bash
nmap -p 21,22,80,443,445 192.168.1.1
```

 **Port Range**
```bash
 nmap -p 1-1000 192.168.1.1
```

**Aggressive Scan (OS + Version + Scripts + Traceroute)**
```bash
nmap -A 192.168.1.1
```

**Vulnerability Scan**
```bash
nmap --script vuln 192.168.1.1
```

**Host Discovery**
```
nmap -sn 192.168.1.0/24
```
This runs an Nmap Host Discovery scan on the entire subnet 192.168.1.0 – 192.168.1.255 and tells you:
- Which IPs are alive/up
- Which IPs are down/not responding

## NMAP Output Formats
```bash
# Normal output
nmap -oN scan.txt 192.168.1.1

# XML output (for tools like Metasploit)
nmap -oX scan.xml 192.168.1.1

# Grepable output
nmap -oG scan.gnmap 192.168.1.1

# All formats at once ⭐ RECOMMENDED
nmap -oA scan_results 192.168.1.1
```


## NMAP Timing Templates

| Template | Name | Use Case |
| :--- | :--- | :--- |
| `-T0` | Paranoid | IDS evasion (very slow) |
| `-T1` | Sneaky | IDS evasion |
| `-T2` | Polite | Reduced bandwidth |
| `-T3` | Normal | Default |
| `-T4` | Aggressive | Fast scan ⭐ Commonly Used |
| `-T5` | Insane | Very fast (may miss ports) |


## NMAP Scripting Engine (NSE)

**Location of Scripts:**
```
ls /usr/share/nmap/scripts/
```

**Script Categories:**
```
auth     - Authentication related
broadcast - Network broadcast
brute    - Brute force attacks
default  - Default scripts (-sC)
discovery - Service discovery
dos      - Denial of service
exploit  - Exploitation
external - External resources
fuzzer   - Fuzzing
intrusive - Intrusive scripts
malware  - Malware detection
safe     - Safe scripts
version  - Version detection
vuln     - Vulnerability detection ⭐
```

**Common NSE Commands:**
```
# Run default scripts
nmap -sC 192.168.1.1

# Run vulnerability scripts
nmap --script vuln 192.168.1.1

# Run specific script
nmap --script=http-title 192.168.1.1

# Run multiple scripts
nmap --script=http-title,http-headers 192.168.1.1

# Run script category
nmap --script=safe 192.168.1.1

# SMB vulnerability check
nmap --script=smb-vuln* 192.168.1.1

# FTP anonymous login check
nmap --script=ftp-anon 192.168.1.1
```



#  Masscan - Fast Port Scanner
alternative to Nmap


```bash
# Scan top ports
masscan 192.168.1.0/24 -p 21,22,80,443,445

# Scan all ports (VERY FAST)
masscan 192.168.1.0/24 -p 0-65535 --rate 10000

# Output to file
masscan 192.168.1.0/24 -p 80,443 -oL output.txt
```


## Port States
| State | Meaning |
| :--- | :--- |
| `open` | Port is accepting connections |
| `closed` | Port is accessible but no service |
| `filtered` | Firewall blocking, can't determine |
| `unfiltered` | Accessible, but can't determine open/closed |
| `open\|filtered` | Can't determine if open or filtered |
| `closed\|filtered` | Can't determine if closed or filtered |
