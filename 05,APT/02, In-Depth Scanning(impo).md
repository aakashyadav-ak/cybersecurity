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
