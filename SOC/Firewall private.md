A Firewall is a network security device (hardware/software) that monitors and filters incoming and outgoing network traffic based on predefined security rules. It acts as a barrier between a trusted internal network and an untrusted external network (like the Internet).

## Types of Firewalls

###  1- Packet Filtering Firewall (1st Generation)
- Works at: Network Layer (Layer 3) & Transport Layer (Layer 4)
- Checks: Source IP, Destination IP, Port, Protocol
- Does NOT inspect packet content
- Fast but basic
- Example: Basic ACLs on routers



### 2- Stateful Inspection Firewall (2nd Generation)
- Works at: Layer 3 & Layer 4
- Tracks the STATE of active connections
- Maintains a STATE TABLE
- Knows if a packet is NEW, ESTABLISHED, or RELATED
- More secure than packet filtering
- Example: Cisco ASA, iptables (Linux)


### 3- Application Layer Firewall / Proxy Firewall (3rd Generation)
- Works at: Application Layer (Layer 7)
- Inspects actual DATA/CONTENT in packets
- Can filter HTTP, FTP, DNS traffic content
- Slower but more thorough
- Example: Squid Proxy


### 4- Next-Generation Firewall (NGFW) 
- Works at: Layer 3 to Layer 7
- Combines traditional firewall + extras:
  ✅ Deep Packet Inspection (DPI)
  ✅ Intrusion Prevention System (IPS)
  ✅ Application Awareness & Control
  ✅ SSL/TLS Inspection
  ✅ User Identity Awareness
  ✅ Threat Intelligence Integration
  ✅ Sandboxing
- Examples: Palo Alto, Fortinet FortiGate, Cisco Firepower, Check Point, Sophos XG


### 5-  Web Application Firewall (WAF)
- Specifically protects WEB APPLICATIONS
- Filters HTTP/HTTPS traffic
- Protects against: SQL Injection, XSS, CSRF, etc.
- Sits between user and web server
- Examples: AWS WAF, Cloudflare WAF, ModSecurity, F5 ASM, Imperva


### 6- Cloud Firewall (FWaaS - Firewall as a Service)
- Cloud-based firewall
- Protects cloud infrastructure
- Examples: Azure Firewall, AWS Security Groups/NACLs, GCP Firewall Rules, Zscaler