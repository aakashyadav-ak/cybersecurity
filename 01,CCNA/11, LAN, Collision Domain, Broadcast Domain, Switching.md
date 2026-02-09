# Cisco's Internetworking Operating System(IOS)

1. LAN Switching Technologies
2. Troubleshoot interface & Cable issues(collisions,errors,duplex speed)
3. Infrastructure Managment
4. Configure & Verify Initial device configuration
5. Configure, verify & troubleshoot basic device hardening 
   a. Local Authentication
   b. secure Password 
   c. Access to Device 
   d. Login banner
6. Ping & Traceroute with extended option
7. Log events


# Types of LAN 
1. SOHO LAN (Small office/Home office)
2. Enterprise LAN

```
┌─────────────────────────────────────────────────────────────────────────┐
│              SOHO TREE & ENTERPRISE MESH NETWORKS                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────┐   ┌─────────────────────────────┐    │
│   │        SOHO TREE            │   │     ENTERPRISE MESH         │    │
│   ├─────────────────────────────┤   ├─────────────────────────────┤    │
│   │                             │   │                             │    │
│   │ • Small Office/Home Office  │   │ • Large Organizations       │    │
│   │ • 1-20 Users                │   │ • 100-10,000+ Users         │    │
│   │ • Hierarchical Structure    │   │ • Highly Redundant          │    │
│   │ • Router → Switch → Devices │   │ • Multiple Interconnections │    │
│   │ • Simple Star/Tree Design   │   │ • Data Center / Campus      │    │
│   │ • Budget-Friendly           │   │ • Maximum Availability      │    │
│   │ • Basic Redundancy          │   │ • Spine-Leaf / Full Mesh    │    │
│   │                             │   │                             │    │
│   └─────────────────────────────┘   └─────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## SOHO 
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SOHO TREE NETWORK DIAGRAM                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│                            ┌─────────────┐                              │
│                            │  INTERNET   │                              │
│                            │    (ISP)    │                              │
│                            └──────┬──────┘                              │
│                                   │                                     │
│                            ┌──────┴──────┐                              │
│                            │    MODEM    │                              │
│                            └──────┬──────┘                              │
│                                   │                                     │
│   ════════════════════════════════════════════════════════════════     │
│   ║                     ROOT LEVEL                               ║     │
│   ════════════════════════════════════════════════════════════════     │
│                                   │                                     │
│                            ┌──────┴──────┐                              │
│                            │   ROUTER    │ ◄── Root Node               │
│                            │ (Gateway)   │     DHCP, NAT, Firewall     │
│                            │ 192.168.1.1 │     Wireless (optional)     │
│                            └──────┬──────┘                              │
│                                   │                                     │
│   ════════════════════════════════════════════════════════════════     │
│   ║                   BRANCH LEVEL                               ║     │
│   ════════════════════════════════════════════════════════════════     │
│                                   │                                     │
│              ┌────────────────────┼────────────────────┐                │
│              │                    │                    │                │
│       ┌──────┴──────┐      ┌──────┴──────┐      ┌──────┴──────┐        │
│       │  SWITCH 1   │      │  SWITCH 2   │      │   WIRELESS  │        │
│       │  (Office)   │      │  (Lab/Work) │      │     AP      │        │
│       │  8-Port     │      │  8-Port     │      │             │        │
│       └──────┬──────┘      └──────┬──────┘      └──────┬──────┘        │
│              │                    │                    │                │
│   ════════════════════════════════════════════════════════════════     │
│   ║                    LEAF LEVEL                                ║     │
│   ════════════════════════════════════════════════════════════════     │
│              │                    │                    │                │
│    ┌─────────┼─────────┐   ┌──────┼──────┐      ┌──────┴──────┐        │
│    │         │         │   │      │      │      │             │        │
│   🖥️        💻        🖨️  🖥️     🖥️    📷     📱    📱    💻       │
│  Desktop  Laptop  Printer Desktop Desktop Camera Phone  Phone Laptop   │
│                                          (PoE)                          │
│                                                                         │
│   IP Range: 192.168.1.0/24                                             │
│   DHCP Pool: 192.168.1.100 - 192.168.1.200                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Enterprise LAN
```
┌─────────────────────────────────────────────────────────────────────────┐
│                   ENTERPRISE MESH DEFINITION                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Enterprise Mesh = High-redundancy network topology for large          │
│                     organizations with multiple interconnections        │
│                                                                         │
│   Key Concepts:                                                         │
│   ══════════════                                                        │
│                                                                         │
│   • Every (or most) nodes connected to multiple other nodes            │
│   • Multiple paths for data to travel                                  │
│   • Eliminates single points of failure                                │
│   • Self-healing capability                                            │
│   • Used in data centers and campus backbones                          │
│                                                                         │
│   Types of Enterprise Mesh:                                             │
│   ═════════════════════════                                             │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                                                                 │  │
│   │   1. FULL MESH         - Every node connected to every other   │  │
│   │                          node (maximum redundancy)             │  │
│   │                                                                 │  │
│   │   2. PARTIAL MESH      - Strategic connections between         │  │
│   │                          critical nodes                        │  │
│   │                                                                 │  │
│   │   3. SPINE-LEAF        - Modern data center mesh design        │  │
│   │      (Clos Network)      (most common today)                   │  │
│   │                                                                 │  │
│   │   4. WIRELESS MESH     - Enterprise wireless with mesh         │  │
│   │      (Campus)            backhaul between APs                  │  │
│   │                                                                 │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   Where Used:                                                           │
│   ════════════                                                          │
│   • Data centers (spine-leaf)                                          │
│   • Campus network backbones                                           │
│   • Financial trading networks                                         │
│   • Healthcare critical systems                                        │
│   • Cloud infrastructure                                               │
│   • Service provider networks                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Collision Domains
#### 1: HUB=
1 collision domain because it multicast so at a time it only process one request that means collision occurs at only one port

#### 2: Switch=
26 collision domain because it has 26 port and every 26 port can communicate at time so collision occurs at 26 port at a time.


```
┌─────────────────────────────────────────────────────────────────────────┐
│                      COLLISION DOMAIN                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Definition:                                                           │
│   ════════════                                                          │
│                                                                         │
│   A collision domain is a network segment where data packets can        │
│   collide with each other when being sent on a shared medium.           │
│                                                                         │
│   When two devices transmit data simultaneously on the same             │
│   collision domain, a COLLISION occurs, and both transmissions fail.   │
│                                                                         │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                                                                 │   │
│   │     Device A                              Device B              │   │
│   │        │                                     │                  │   │
│   │        │   ══════► Data Frame               │                  │   │
│   │        │              │                      │                  │   │
│   │        │              │    Data Frame ◄══════│                  │   │
│   │        │              │         │            │                  │   │
│   │        │              ▼         ▼            │                  │   │
│   │        │           ┌─────────────┐           │                  │   │
│   │        │           │  COLLISION! │           │                  │   │
│   │        │           │   💥💥💥    │           │                  │   │
│   │        │           └─────────────┘           │                  │   │
│   │        │                                     │                  │   │
│   │   Both transmissions are corrupted and must be retransmitted   │   │
│   │                                                                 │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   Key Concept:                                                          │
│   • Collisions ONLY occur in HALF-DUPLEX communication                 │
│   • Modern FULL-DUPLEX switches eliminate collisions                   │
│   • Legacy devices (Hubs, Coax) create large collision domains        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Broadcast Domain
#### Hub= 1 Broadcast Domain
#### Switch= 1 broadcast domain
because it once only one packet can transfer on all 26 ports.



# Switching
Switching is the process of forwarding data packets/frames from a source to a destination within a network(LAN). A switch is a network device that connects multiple devices and uses MAC addresses to forward data at Layer 2 (DATA LINK LAYER).

Switching is a Layer 2 (Data Link Layer) process where a network switch forwards frames based on MAC addresses. It creates a MAC address table (CAM table) dynamically by learning source MAC addresses on incoming frames.

```
┌─────────────────────────────────────────────────┐
│           SWITCHING BENEFITS                    │
├─────────────────────────────────────────────────┤
│ ✓ Dedicated bandwidth per port                  │
│ ✓ Full-duplex communication                     │
│ ✓ Each port = Separate collision domain         │
│ ✓ MAC address learning & filtering              │
│ ✓ Low latency & high speed                      │
│ ✓ Supports VLANs (network segmentation)         │
│ ✓ More secure than hubs                         │
└─────────────────────────────────────────────────┘
```
### Three Switch Functions at Layer 2:-

#### 1.Address learning - 
Layer 2 switches and bridges remember the source hardware address of each frame received on an interface, and they enter this information into a
MAC database called a forward/filter table.

#### 2.Forward/filter decisions - 
When a frame is received on an interface, the switch looks at the destination hardware address and finds the exit interface in the MAC database.
The frame is only forwarded out the specified destination port.

#### 3.Loop avoidance -
If multiple connections between switches are created for redundancy purposes, network loops can occur. Spanning Tree Protocol (STP) is
used to stop network loops while still permitting redundancy.
switch avoids loop by default STP protocol is enabled on the switch to avoid loop. STP keeps 1 link in the forwarding state and put all other link-blocking states to

### STP (Spanning Tree Protocol)
 Prevent Layer 2 switching loops in networks with redundant links.
It prevents loop by shutting down a line thats not needed or making a loop.
A STP packet is generate every 10sec to check loop occurrence and prevent the loop by downing  the line and also up the line when needed.


## Router/Switch Packet Switching Methods
These are methods used by routers (especially Cisco) to forward packets from source to destination.

![[Screenshot (98) 1.png]]
#### 1. Process Switching

- Oldest and slowest method
- **Every packet processed by CPU**
- CPU handles all routing decisions


```
Packet Arrives
      ↓
CPU receives packet
      ↓
CPU looks up routing table
      ↓
CPU determines exit interface
      ↓
CPU forwards packet
      ↓
(Repeat for EVERY packet)
```

#### 2. Fast Switching (Route Cache)


- Also called route-cache switching (called switch engine)
- First packet is process-switched
- Cache stores destination info for subsequent packets
- Open standard (not Cisco proprietary)

```
First Packet:
      ↓
Process switched (slow)
      ↓
Result stored in ROUTE CACHE
      ↓
Subsequent Packets:
      ↓
Check route cache
      ↓
Forward using cached info (fast)
```

##### Route Cache Structure
```
┌─────────────────┬──────────────┬─────────────┬─────────────┐
│  Destination IP │ Next-Hop IP  │ Interface   │ MAC Header  │
├─────────────────┼──────────────┼─────────────┼─────────────┤
│  192.168.1.0    │ 10.0.0.2     │ Gi0/1       │ AA:BB:CC... │
│  172.16.0.0     │ 10.0.0.3     │ Gi0/2       │ DD:EE:FF... │
└─────────────────┴──────────────┴─────────────┴─────────────┘
```

##### RIB (Routing Information Base)
What is RIB?

- Also called Routing Table
- Lives in Control Plane( in CPU )
- Contains all routes learned from various sources
- Maintained by CPU/Route Processor
- Selects best path based on administrative distance and metrics


#### ==3. CEF Switching (Cisco Express Forwarding)==

- Fastest and most preferred method
- Cisco proprietary
- Uses pre-built tables
- Default on modern Cisco routers
##### Key Components
###### a) FIB (Forwarding Information Base)


- **Mirror of routing table (RIB) and Use it as FIB and store it in temporary memory like RAM (switch engine of switch) after shutdown of switch FIB is rested and again on first connect it clones RIB and store it in switch engine.**
- Optimized for fast lookup

```
┌─────────────────┬──────────────┬─────────────┐
│  Prefix/Network │ Next-Hop     │ Interface   │
├─────────────────┼──────────────┼─────────────┤
│  192.168.1.0/24 │ 10.0.0.2     │ Gi0/1       │
│  172.16.0.0/16  │ 10.0.0.3     │ Gi0/2       │
│  0.0.0.0/0      │ 10.0.0.1     │ Gi0/0       │
└─────────────────┴──────────────┴─────────────┘
```

**FIB (Forwarding Information Base)**
What is FIB?

- **Lives in Data Plane (switch engine) or called RAM of switch**
- **Optimized copy of best routes from RIB**
- **Used for actual packet forwarding**
- Hardware-based lookups (ASIC/TCAM)
- Part of CEF (Cisco Express Forwarding)

###### b) Adjacency Table
```
┌──────────────┬───────────────────┬─────────────┐
│  Next-Hop IP │ Layer 2 Header    │ Interface   │
├──────────────┼───────────────────┼─────────────┤
│  10.0.0.2    │ AA:BB:CC:DD:EE:01 │ Gi0/1       │
│  10.0.0.3    │ AA:BB:CC:DD:EE:02 │ Gi0/2       │
└──────────────┴───────────────────┴─────────────┘
```


- Contains Layer 2 information
- Pre-computed MAC addresses


## Planes on Router / Traffic on Router 
![[Pasted image 20260129143417.png]]

