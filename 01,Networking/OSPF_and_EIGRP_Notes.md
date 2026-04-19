# 📘 OSPF vs EIGRP — Detailed Notes


---

## 📋 Table of Contents

1. [Introduction to Routing Protocols](#introduction-to-routing-protocols)
2. [OSPF (Open Shortest Path First)](#ospf-open-shortest-path-first)
3. [EIGRP (Enhanced Interior Gateway Routing Protocol)](#eigrp-enhanced-interior-gateway-routing-protocol)
4. [OSPF vs EIGRP — Comparison](#ospf-vs-eigrp--comparison)
5. [When to Use Which?](#when-to-use-which)
6. [Key Takeaways](#key-takeaways)

---

## 🔹 Introduction to Routing Protocols

### What is a Routing Protocol?

Imagine you're in a big city and need to find the fastest way to get from point A to point B. You could:
- Ask locals for directions
- Use a GPS app
- Look at a map and figure it out yourself

**Routers do the same thing!** They need to figure out the best path to send data across a network. A **routing protocol** is like the "language" routers use to talk to each other and share information about network paths.

### Types of Routing Protocols

| Type                                | Description                                     | Examples         |
| ----------------------------------- | ----------------------------------------------- | ---------------- |
| **IGP** (Interior Gateway Protocol) | Used *within* a single organization/network     | OSPF, EIGRP, RIP |
| **EGP** (Exterior Gateway Protocol) | Used *between* different organizations/networks | BGP              |

### Distance Vector vs Link State

Before diving in, understand these two approaches:

**📍 Distance Vector (Like asking for directions)**
- Routers only know the *distance* and *direction* to a destination
- They don't know the full network map
- Example: "Network X is 3 hops away through Router Y"
- Protocols: RIP, EIGRP (advanced distance vector)

**🗺️ Link State (Like having a full map)**
- Every router builds a *complete map* of the network
- Each router knows all paths and can calculate the best one
- Example: "I know every router, every link, and their speeds"
- Protocols: OSPF, IS-IS

---

## 🟢 OSPF (Open Shortest Path First)

### What is OSPF?

**OSPF** is a **Link-State routing protocol** that is:
- **Open standard** — works on any brand of router (Cisco, Juniper, HP, etc.)
- **Widely used** — one of the most popular routing protocols in the world
- **Fast converging** — quickly adapts when network changes happen
- **Scalable** — works in small and very large networks

### How OSPF Works — Step by Step

Think of OSPF like a group of cartographers (map makers) working together:

#### Step 1: Neighbor Discovery 👋
- When OSPF routers connect, they say "Hello!" to each other
- They send **Hello packets** to discover neighbors
- If both routers agree on settings, they become **neighbors**

```
Router A ───Hello───→ Router B
Router A ←──Hello─── Router B
"We agree! Let's become neighbors!"
```

#### Step 2: Exchange Information 📡
- Neighbors exchange summaries of their link-state databases
- They figure out what information the other router is missing

#### Step 3: Build the Full Map 🗺️
- Each router sends its complete link-state information
- This information is called **LSA (Link-State Advertisement)**
- Every router collects LSAs and builds the **LSDB (Link-State Database)**
- The LSDB is like a complete map of the entire network

#### Step 4: Calculate Best Paths 🧮
- Each router runs the **SPF (Shortest Path First) algorithm** — also called **Dijkstra's algorithm**
- This calculates the shortest (best cost) path to every destination
- The results go into the **Routing Table**

#### Step 5: Maintain the Map 🔄
- Routers send Hello packets every 10 seconds (by default)
- If a neighbor doesn't respond for 40 seconds, it's considered down
- When topology changes, routers immediately flood updated LSAs

### OSPF Key Concepts

#### 🔹 Router ID
- A unique identifier for each OSPF router
- Usually the highest IP address on a loopback interface
- If no loopback exists, highest IP on any active interface

#### 🔹 Areas 🏘️
OSPF divides networks into **areas** to reduce complexity:

```
                    ┌─────────────────────┐
                    │    Area 0 (Backbone) │
                    │      Must exist!      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────┴─────┐  ┌──────┴───────┐  ┌─────┴────────┐
    │   Area 1      │  │   Area 2     │  │   Area 3     │
    │               │  │              │  │              │
    └───────────────┘  └──────────────┘  └──────────────┘
```

**Why Areas?**
- Reduces the size of the LSDB on each router
- Limits how far LSA updates travel
- Improves performance and scalability

**Area Types:**
| Area Type | Description |
|-----------|-------------|
| **Backbone Area (Area 0)** | The core area; all other areas must connect to it |
| **Standard Area** | Normal area with full routing information |
| **Stub Area** | Blocks external routes; uses a default route instead |
| **Totally Stubby Area** | Blocks external AND inter-area routes |
| **NSSA** (Not-So-Stubby Area) | Like stub, but allows limited external route injection |

#### 🔹 Router Types

| Type | Description |
|------|-------------|
| **Internal Router** | All interfaces in the same area |
| **ABR** (Area Border Router) | Connects different areas; has interfaces in multiple areas |
| **ASBR** (Autonomous System Boundary Router) | Connects OSPF to external routing protocols (like BGP) |
| **Backbone Router** | Has at least one interface in Area 0 |

#### 🔹 LSA Types (Link-State Advertisements)

| LSA Type | Name | Description |
|----------|------|-------------|
| Type 1 | Router LSA | Generated by every router; describes its links |
| Type 2 | Network LSA | Generated by DR on broadcast networks |
| Type 3 | Summary LSA | Generated by ABRs; summarizes routes between areas |
| Type 4 | ASBR Summary LSA | Tells routers how to reach the ASBR |
| Type 5 | External LSA | Routes redistributed from outside OSPF |
| Type 7 | NSSA External LSA | External routes in NSSA areas |

#### 🔹 DR and BDR (Designated Router & Backup)

On **broadcast networks** (like Ethernet), OSPF elects:
- **DR (Designated Router)** — central point for LSA exchange
- **BDR (Backup Designated Router)** — backup if DR fails

**Why?** Without DR/BDR, every router would form adjacency with every other router, creating too many connections:
- With DR/BDR: **n-1** adjacencies
- Without DR/BDR: **n(n-1)/2** adjacencies

```
Without DR/BDR (Messy!):          With DR/BDR (Clean!):

   A ─── B                         A ───┐
   │╲   │╲                           │   │╲
   │ ╲  │ ╲                          │   │ ╲
   │  ╲ │  ╲                    B ───DR───BDR─── C
   │   ╲│   ╲                          │   │ ╱
   C ─── D                             │   │╱
                                       D ───┘
```

**Election Rules:**
1. Highest OSPF priority wins (default = 1, 0 = never elected)
2. If tie, highest Router ID wins

#### 🔹 OSPF Metric (Cost)

OSPF uses **cost** to determine the best path.

```
Cost = Reference Bandwidth / Interface Bandwidth
```

- Default reference bandwidth = **100 Mbps**
- Lower cost = better path
- Cost is based on **bandwidth** (faster link = lower cost)

| Link Speed | Cost |
|------------|------|
| 10 Mbps | 10 |
| 100 Mbps | 1 |
| 1 Gbps | 1 |
| 10 Gbps | 1 |

⚠️ **Note:** With modern high-speed links, the default reference bandwidth causes problems (everything shows cost 1). It should be adjusted:
```
auto-cost reference-bandwidth 10000  (for 10 Gbps reference)
```

### OSPF Neighbor States

Routers go through states when forming adjacency:

| State | Description |
|-------|-------------|
| **Down** | No Hello received |
| **Init** | Hello received, but my Router ID not in it |
| **2-Way** | Bidirectional communication established (DR/BDR election happens here) |
| **ExStart** | Negotiating who starts the exchange |
| **Exchange** | Exchanging DBD (Database Description) packets |
| **Loading** | Requesting missing LSAs |
| **Full** | Adjacency complete — databases are synchronized ✅ |

### OSPF Network Types

| Type | Description | DR/BDR? | Hello Timer |
|------|-------------|---------|-------------|
| **Broadcast** | Ethernet LANs | Yes | 10 seconds |
| **Point-to-Point** | Serial links, PPP | No | 10 seconds |
| **Non-Broadcast** | Frame Relay | Yes | 30 seconds |
| **Point-to-Multipoint** | Hub-and-spoke | No | 30 seconds |

### OSPF Configuration Example (Cisco)

```cisco
! Enable OSPF with process ID 1
router ospf 1

! Set Router ID (optional but recommended)
router-id 1.1.1.1

! Advertise networks
network 10.0.0.0 0.0.0.255 area 0
network 192.168.1.0 0.0.0.255 area 1

! Adjust reference bandwidth for modern links
auto-cost reference-bandwidth 10000

! Set interface cost manually
interface GigabitEthernet0/0
 ip ospf cost 10
```

### OSPF Pros and Cons

| ✅ Advantages | ❌ Disadvantages |
|---------------|-----------------|
| Open standard (vendor-neutral) | Complex to configure and troubleshoot |
| Fast convergence | High CPU and memory usage (LSDB + SPF) |
| No routing loops | Requires hierarchical design (areas) |
| Scales well with areas | Equal-cost load balancing only (max 4-16 paths) |
| Supports VLSM and CIDR | DR/BDR election can be tricky |
| Authentication support | All routers in an area must have identical LSDB |

---

## 🟠 EIGRP (Enhanced Interior Gateway Routing Protocol)

### What is EIGRP?

**EIGRP** is an **Advanced Distance Vector** (or Hybrid) routing protocol that is:
- **Cisco proprietary** — originally only worked on Cisco devices (now partially open)
- **Very fast convergence** — often faster than OSPF
- **Easy to configure** — simpler than OSPF
- **Bandwidth efficient** — only sends updates when changes occur

### How EIGRP Works — Step by Step

Think of EIGRP like a smart delivery service:

#### Step 1: Neighbor Discovery 👋
- Routers send **Hello packets** to discover neighbors
- Hello interval: 5 seconds (default), Hold timer: 15 seconds
- On slow links (< T1): Hello every 60 seconds, Hold 180 seconds
- No need for areas or DR/BDR!

#### Step 2: Exchange Routes 📡
- Neighbors exchange their **entire routing table** (only once, at startup)
- After that, only **changes** are sent (partial updates)

#### Step 3: Calculate Best Paths 🧮
- EIGRP uses the **DUAL algorithm** (Diffusing Update Algorithm)
- Calculates the best path and keeps a **backup path** ready
- No need to recalculate everything when a link fails!

#### Step 4: Maintain Routes 🔄
- Only sends updates when something changes
- Uses reliable transport (RTP) to ensure updates are received

### EIGRP Key Concepts

#### 🔹 Composite Metric

EIGRP's metric is more sophisticated than OSPF's simple cost. It considers **multiple factors**:

```
Metric = 256 × [(K1 × Bandwidth) + (K2 × Bandwidth)/(256 - Load) + (K3 × Delay)]
         × [K5/(Reliability + K4)]   (if K5 ≠ 0)
```

**Simplified (default K values: K1=1, K3=1, K2=K4=K5=0):**

```
Metric = 256 × (Minimum Bandwidth + Sum of Delays)
```

**What this means:**
- **Bandwidth**: The slowest link in the path (bottleneck)
- **Delay**: The sum of delays across all links
- **Load**: How busy the link is (0-255, not used by default)
- **Reliability**: Link quality (0-255, not used by default)
- **MTU**: Maximum Transmission Unit (advertised but not used in metric)

**Example Calculation:**

```
Path: A ──100Mbps──→ B ──10Mbps──→ C ──1Gbps──→ D

Minimum Bandwidth = 10 Mbps (the bottleneck)
  = 10,000 Kbps
  = 100,000,000 / 10,000 = 10,000 (in EIGRP units)

Total Delay = delay(A→B) + delay(B→C) + delay(C→D)

Final Metric = 256 × (10,000 + Total Delay)
```

| Link Speed | Bandwidth Value | Default Delay (microseconds) |
|------------|-----------------|------------------------------|
| 10 Mbps | 1,000,000 / 10 = 100,000 | 1,000,000 / 10 = 100,000 |
| 100 Mbps | 1,000,000 / 100 = 10,000 | 100,000 |
| 1 Gbps | 1,000,000 / 1,000 = 1,000 | 10,000 |
| 10 Gbps | 1,000,000 / 10,000 = 100 | 1,000 |

#### 🔹 DUAL Algorithm (Diffusing Update Algorithm)

This is EIGRP's secret weapon! Here's how it works:

**Key Terms:**

| Term | Meaning |
|------|---------|
| **FD (Feasible Distance)** | Best metric to reach a destination |
| **RD/AD (Reported/Advertised Distance)** | Neighbor's metric to reach the destination |
| **Successor** | Best next-hop router (primary path) |
| **Feasible Successor** | Backup next-hop router (backup path) |

**The Feasibility Condition (FC):**

```
A neighbor can be a Feasible Successor if:
    RD < FD of the current Successor
```

**Why is this brilliant?** It guarantees **loop-free backup paths**! If a neighbor's distance to the destination is LESS than my current best distance, that neighbor definitely isn't routing through me — so there's no loop.

**Example:**

```
        RD=15                    RD=25
   B ──────────→ Destination   C ──────────→ Destination
  /                                 \
 / FD=20                             \ FD=30
A                                     A

B's RD (15) < A's FD (20) ✅    C's RD (25) > A's FD (20) ❌
B is a Feasible Successor!     C is NOT a Feasible Successor
```

When the primary path fails:
1. Check topology table for a Feasible Successor
2. If one exists → **instant switchover** (no recalculation needed!)
3. If none exists → query neighbors for a new path

#### 🔹 EIGRP Tables

| Table | Purpose |
|-------|---------|
| **Neighbor Table** | Lists all EIGRP neighbors and their status |
| **Topology Table** | All learned routes with their metrics (successors + feasible successors) |
| **Routing Table** | Only the best routes (successors) are installed here |

#### 🔹 Packet Types

| Packet | Purpose | Reliable? |
|--------|---------|-----------|
| **Hello** | Discover and maintain neighbors | No (multicast) |
| **Update** | Share routing information | Yes (when needed) |
| **Query** | Ask neighbors for route info when no FS exists | Yes |
| **Reply** | Answer to a Query | Yes |
| **ACK** | Acknowledge reliable packets | No |

#### 🔹 Unequal Cost Load Balancing

Unlike OSPF (which only does equal-cost), EIGRP can load balance across **unequal cost** paths!

```
variance <multiplier>
```

**How it works:**
- Any route with metric ≤ (FD × variance) can be used
- Traffic is distributed proportionally to the metric

```
Example:
  Path 1 (FD = 20,000) — Primary
  Path 2 (FD = 30,000) — Backup

variance 2

30,000 ≤ (20,000 × 2) = 40,000 ✅
Path 2 is now used for load balancing!
```

#### 🔹 Summarization & Discontiguous Networks

- EIGRP can summarize routes **anywhere** in the network (not just at area borders like OSPF)
- Use `ip summary-address eigrp <AS> <network> <mask>` on interfaces

### EIGRP Configuration Example (Cisco)

```cisco
! Enable EIGRP with Autonomous System number 100
router eigrp 100

! Set Router ID (optional but recommended)
eigrp router-id 1.1.1.1

! Advertise networks (wildcard mask)
network 10.0.0.0 0.0.0.255
network 192.168.1.0 0.0.0.255

! Disable automatic summarization (important!)
no auto-summary

! Adjust metric K-values (usually keep defaults)
metric weights 0 1 0 1 0 0

! Set variance for unequal cost load balancing
variance 2

! Interface-level configuration
interface GigabitEthernet0/0
 ip hello-interval eigrp 100 5
 ip hold-time eigrp 100 15
```

### EIGRP Named Mode (Modern Configuration)

```cisco
router eigrp MYCOMPANY
 address-family ipv4 autonomous-system 100
  network 10.0.0.0 0.0.0.255
  network 192.168.1.0 0.0.0.255
  eigrp router-id 1.1.1.1
  no auto-summary
  af-interface default
   passive-interface default
  exit-af-interface
  af-interface GigabitEthernet0/0
   no passive-interface
  exit-af-interface
 exit-address-family
```

### EIGRP for IPv6

```cisco
! Classic mode
ipv6 router eigrp 100
 eigrp router-id 1.1.1.1
 no shutdown

interface GigabitEthernet0/0
 ipv6 eigrp 100
```

### EIGRP Pros and Cons

| ✅ Advantages | ❌ Disadvantages |
|---------------|-----------------|
| Extremely fast convergence | Originally Cisco proprietary (now partially open) |
| Easy to configure and troubleshoot | Not as widely supported on non-Cisco devices |
| Low bandwidth usage (partial updates) | Can have suboptimal routing due to feasibility condition |
| Unequal cost load balancing | Complex DUAL can be hard to troubleshoot |
| Simple hierarchical design not required | Query process can cause SIA (Stuck In Active) issues |
| Loop-free by design (DUAL) | Less documentation and community support vs OSPF |
| Flexible summarization | |

---

## 📊 OSPF vs EIGRP — Comparison

| Feature | OSPF | EIGRP |
|---------|------|-------|
| **Type** | Link-State | Advanced Distance Vector (Hybrid) |
| **Standard** | Open (RFC 2328) | Cisco Proprietary (partially opened) |
| **Algorithm** | Dijkstra (SPF) | DUAL |
| **Metric** | Cost (bandwidth only) | Composite (bandwidth + delay + optional) |
| **Convergence** | Fast | Very Fast |
| **Resource Usage** | Higher (CPU + Memory) | Lower |
| **Hierarchy** | Areas (required for large networks) | No areas needed (optional summarization) |
| **Load Balancing** | Equal-cost only | Equal AND unequal cost |
| **Updates** | Periodic (LSA refresh every 30 min) | Triggered only (on change) |
| **Network Design** | Must be hierarchical | Flat design works fine |
| **DR/BDR** | Required on broadcast networks | Not needed |
| **Scalability** | Excellent (with areas) | Good to Excellent |
| **Vendor Support** | All vendors | Primarily Cisco |
| **Configuration** | More complex | Simpler |
| **Loop Prevention** | By design (SPF tree) | By design (Feasibility Condition) |

---

## 🤔 When to Use Which?

### Choose OSPF When:
- ✅ Multi-vendor environment (Cisco + Juniper + others)
- ✅ Large enterprise with clear hierarchical design
- ✅ Industry standard is required
- ✅ You need proven scalability with areas
- ✅ Team has OSPF expertise

### Choose EIGRP When:
- ✅ All-Cisco (or mostly Cisco) environment
- ✅ Quick and easy deployment is priority
- ✅ You need unequal cost load balancing
- ✅ Limited bandwidth for routing updates
- ✅ Simpler management is desired
- ✅ You don't want to design areas

---

## 🎯 Key Takeaways

### OSPF in One Paragraph:
> OSPF is an open-standard link-state protocol where every router builds a complete map of the network. It divides networks into areas (with Area 0 as the backbone) to scale efficiently. It uses cost (based on bandwidth) as its metric and the SPF algorithm to calculate loop-free paths. It's complex but powerful and works everywhere.

### EIGRP in One Paragraph:
> EIGRP is a Cisco-developed hybrid protocol that combines the best of distance vector and link-state approaches. It uses the brilliant DUAL algorithm to achieve lightning-fast convergence by keeping backup paths ready. It uses a composite metric (bandwidth + delay) and supports unequal cost load balancing. It's simpler to configure but mostly limited to Cisco environments.

### Memory Tricks 🧠

| Concept | Trick |
|---------|-------|
| **OSPF = Open** | Works with **O**ther vendors |
| **OSPF = Areas** | Think "**O**rganized **S**ections **P**er **F**loor" |
| **EIGRP = Easy** | **E**asy configuration |
| **EIGRP = Enhanced** | It's RIP's smarter cousin |
| **DUAL** | **D**on't **U**se **A**lternate **L**oops (backup paths are loop-free!) |
| **OSPF Cost** | **C**ost = **C**apacity (bandwidth) |
| **EIGRP Metric** | **B**andwidth + **D**elay = "**B**est **D**irection" |

---

## 📝 Quick Reference Commands

### OSPF

```cisco
show ip ospf neighbor          # View OSPF neighbors
show ip ospf database          # View LSDB
show ip ospf interface         # OSPF interface details
show ip route ospf             # OSPF routes only
clear ip ospf process          # Reset OSPF (confirm needed)
debug ip ospf adj              # Debug adjacency formation
```

### EIGRP

```cisco
show ip eigrp neighbors        # View EIGRP neighbors
show ip eigrp topology         # View topology table
show ip eigrp interfaces       # EIGRP interface details
show ip route eigrp            # EIGRP routes only
debug eigrp packets            # Debug EIGRP packets
show ip protocols              # Verify routing protocol config
```

---

## 🔗 Additional Resources

- **OSPF RFC**: RFC 2328
- **EIGRP Info RFC**: RFC 7868
- **Cisco Documentation**: Cisco.com → Routing → OSPF/EIGRP
- **Packet Tracer / GNS3 / EVE-NG**: Great for hands-on practice

---

> 💡 **Pro Tip:** In the real world, OSPF is more common in large enterprises and service providers due to its open standard status. EIGRP is popular in Cisco-centric environments, especially mid-sized businesses. Both are excellent protocols — the choice usually comes down to vendor requirements and team expertise.

---

*Notes compiled for networking study and reference. Last updated: 2025*
