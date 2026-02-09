# Networking 

---

## 1. Fundamentals & Models
- [x] **OSI Model** (Deep Dive)
	- [x] Layer 1-3 (Physical, Data, Network) - *Hardware/Routing*
	- [x] Layer 4 (Transport) - *Firewalls/Connections*
	- [x] Layer 7 (Application) - *Payloads/Exploits*
- [x] **TCP/IP Model** vs OSI
- [x] **Encapsulation & Decapsulation** (Headers & Trailers)
- [x] **The "Holy Trinity" Interaction**
	- [x] MAC Address (Physical ID)
	- [x] IP Address (Logical Location)
	- [x] Port Number (Specific Service/App)

## 2. IP Addressing & Subnetting
- [x] **IPv4 Structure**
- [x] **CIDR Notation** (/24, /16, /32)
- [x] **Subnetting** (Calculate Network ID, Broadcast ID, Host range)
- [x] **Public vs Private IP Ranges** (RFC 1918)
- [x] **NAT Mechanics** (Critical for Logs)
	- [ ] SNAT (Source NAT)
	- [ ] DNAT (Destination NAT / Port Forwarding)
	- [ ] PAT (Port Address Translation)
- [ ] **IPv6 Basics** (Just structure and types)

## 3. Core Protocols (The "How It Works")
*Focus on the header structure and handshake process.*
- [x] **ARP**
	- [x] How it resolves IP to MAC
	- [x] *Attack Vector:* ARP Spoofing/Poisoning
- [ ] **ICMP**
	- [ ] Types & Codes (Echo Request/Reply, Unreachable)
	- [ ] *Attack Vector:* Smurf attacks, Ping of Death, C2 over ICMP
- [x] **TCP**
	- [x] 3-Way Handshake (SYN, SYN-ACK, ACK)
	- [x] TCP Flags (SYN, ACK, FIN, RST, PSH, URG)
	- [x] *Attack Vector:* SYN Floods, RST injection
- [x] **UDP**
	- [x] Connectionless nature
	- [ ] *Attack Vector:* UDP Flood, Amplification attacks
- [ ] **DNS**
	- [ ] A, AAAA, CNAME, MX, TXT records
	- [ ] Recursive vs Iterative queries
	- [ ] *Attack Vector:* DNS Poisoning, Zone Transfers, DNS Tunneling
- [x] **DHCP**
	- [x] DORA Process (Discover, Offer, Request, Acknowledge)
	- [ ] *Attack Vector:* Starvation attacks, Rogue DHCP
- [ ] **HTTP/HTTPS & TLS** (Critical Add-on)
	- [ ] Headers, Methods (GET, POST), Status Codes
	- [ ] SSL/TLS Handshake basics

## 4. Ports & Services
- [x] **Common Ports**
	- [ ] FTP (20/21)
	- [ ] SSH (22)
	- [ ] Telnet (23)
	- [ ] SMTP (25)
	- [ ] DNS (53)
	- [ ] HTTP/HTTPS (80/443)
	- [ ] SMB (445)
	- [ ] RDP (3389)
- [ ] **Service Binding** (Listening vs Established)
- [ ] **Reconnaissance**
	- [ ] Service Fingerprinting
	- [ ] Banner Grabbing

## 5. Switching (Layer 2)
- [ ] **VLANs** (Segmentation security)
- [ ] **Trunking** (802.1Q tagging)
- [ ] **MAC Address Table** (CAM Table)
- [ ] **Inter-VLAN Routing** (Router on a stick / L3 Switch)
- [ ] **Layer 2 Attacks**
	- [ ] MAC Flooding
	- [ ] VLAN Hopping

## 6. Routing (Layer 3)
- [ ] **Router Functions** (Packet forwarding decisions)
- [ ] **Static vs Dynamic** (Concept only)
- [ ] **Default Gateway** importance
- [ ] **Reading a Routing Table**
- [ ] **TTL** (Time To Live) and Loops

## 7. Security Devices & Concepts
- [x] **Firewalls**
	- [ ] Stateless (ACLs) vs Stateful (Session tracking)
	- [ ] Next-Gen (Deep Packet Inspection)
- [x] **Access Control Lists (ACLs)**
	- [ ] Allow/Deny logic
	- [ ] Implicit Deny
- [x] **IDS vs IPS** (Detection vs Prevention)
- [x] **Proxies** (Forward vs Reverse)
- [ ] **WAF** (Web Application Firewall basics)
- [ ] **VPNs** (Tunneling & Encryption concepts)

## 8. Practical Skills (The "Do" Part)
- [ ] **Wireshark** (Reading PCAP files, following streams)
- [ ] **Nmap** (Port scanning, OS detection)
- [ ] **Netcat** (Listener/Client connections)
- [ ] **CLI Tools**
	- [ ] `ping`, `tracert/traceroute`
	- [ ] `netstat -ano` (Active connections)
	- [ ] `nslookup / dig` (DNS queries)
	- [ ] `arp -a`
	- [ ] `ipconfig / ifconfig`