
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

**So you can access internal network services like:**
- RDP (3389)
- SMB (445)
- WinRM (5985)
- HTTP (80/443)
- MSSQL (1433)