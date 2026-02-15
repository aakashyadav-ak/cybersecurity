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
```
 nmap -p 1-1000 192.168.1.1
```

**Aggressive Scan (OS + Version + Scripts + Traceroute)**
```
nmap -A 192.168.1.1
```