
Learn how to access internal services through a compromised machine using:
- Port Forwarding
- Tunneling
- Pivoting

**This is used when:**
- the target network has internal-only systems
- ports are blocked by firewall
- you have access to one machine and want to reach deeper machines

## 1) Port Forwarding
Redirect one port to another machine.

Example:
- You access: `127.0.0.1:8080`
- It forwards to: `10.10.10.20:80`

---

## 2) Tunneling
Creating a path through a blocked network using a proxy/tunnel.

---

## 3) Pivoting
Using a compromised machine as a "bridge" to attack deeper internal machines.


# 01: Port Redirection and Tunneling Using Chisel

## Chisel
Chisel is a fast TCP/HTTP tunneling tool.
Chisel is used for tunneling + pivoting

**It creates a tunnel between:**
- Attacker (Kali)
- Victim (compromised machine)
```
Architecture:
┌──────────────┐         HTTP(S)          ┌──────────────┐
│ Chisel       │◄──────────────────────────┤ Chisel       │
│ Client       │      Encrypted Tunnel     │ Server       │
└──────────────┘                           └──────────────┘
      │                                           │
      │                                           │
   Local App                               Remote Service
```

**So you can access internal network services like:**
- RDP (3389)
- SMB (445)
- WinRM (5985)
- HTTP (80/443)
- MSSQL (1433)


#### Need of Tunneling
```
Scenario 1: Firewall Blocking
├── Internal server has SSH (port 22)
├── Firewall blocks port 22 from outside
└── Solution: Tunnel through allowed port (80/443)

Scenario 2: Pivoting
├── You compromised Machine A
├── Machine A can reach Machine B
├── You cannot directly reach Machine B
└── Solution: Tunnel through Machine A

Scenario 3: Bypassing Network Restrictions
├── Company blocks certain websites/ports
├── You have access to external server
└── Solution: Tunnel traffic through your server
```

#### Types of Port Forwarding
```
LOCAL PORT FORWARDING:
Your PC ──→ Tunnel ──→ Target Server ──→ Internal Service
(Port 8080)        (Port 22)         (Port 3306)

REVERSE PORT FORWARDING:
Target Server ──→ Tunnel ──→ Your PC ──→ Internet
(Internal)              (Port 8080)    (Blocked service)

SOCKS PROXY:
Your Apps ──→ SOCKS Proxy ──→ Tunnel ──→ Target Network
(Browser)    (Port 1080)              (All services)
```


##  Installation and Setup
### Download Chisel
#### Method 1: Pre-compiled Binaries (Recommended)
```bash
# Download latest release
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz

# Extract
gunzip chisel_1.9.1_linux_amd64.gz

# Make executable
chmod +x chisel_1.9.1_linux_amd64
mv chisel_1.9.1_linux_amd64 chisel

# Verify
./chisel --version
```

#### Method 2: Using APT (Kali Linux)
```bash
sudo apt update
sudo apt install chisel -y
```

## Transfer Chisel to Target

**Because Chisel works like a tunnel bridge:**

1) Chisel Server (runs on Kali)
- waits for a connection
- creates the tunnel endpoint on attacker side

1) Chisel Client (runs on Windows)
- connects back to Kali
- forwards internal ports through itself