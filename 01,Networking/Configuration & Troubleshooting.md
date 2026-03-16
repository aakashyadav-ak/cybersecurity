

---

# 1. Basic Router Configuration

## Access Router CLI

```
Router> enable
Router# configure terminal
Router(config)#
```

---

## Set Hostname

```
Router(config)# hostname R1
```

Result:

```
R1(config)#
```

---

## Configure Interface IP Address

Example:

```
R1(config)# interface gigabitEthernet0/0
R1(config-if)# ip address 192.168.1.1 255.255.255.0
R1(config-if)# no shutdown
```

Explanation:

```
interface → select port
ip address → assign IP
no shutdown → enable interface
```

---

## Check Interface Status

```
show ip interface brief
```

Example output:

```
Interface        IP Address     Status
Gig0/0           192.168.1.1    up
Gig0/1           unassigned     down
```

---

# 2. Basic Switch Configuration

Enter configuration mode:

```
Switch> enable
Switch# configure terminal
```

---

## Set Hostname

```
Switch(config)# hostname S1
```

---

## Assign IP to Switch (Management)

```
S1(config)# interface vlan 1
S1(config-if)# ip address 192.168.1.2 255.255.255.0
S1(config-if)# no shutdown
```

Default gateway:

```
S1(config)# ip default-gateway 192.168.1.1
```

---

# 3. Configure Static Route

Static route tells router **how to reach remote network**.

Example:

```
R1(config)# ip route 10.0.0.0 255.255.255.0 192.168.1.2
```

Meaning:

```
Destination network → 10.0.0.0
Next hop → 192.168.1.2
```

---

# 4. Configure Default Route

Used for **unknown networks (internet)**.

```
R1(config)# ip route 0.0.0.0 0.0.0.0 192.168.1.1
```

---

# 5. Verify Routing Table

```
show ip route
```

Example:

```
C 192.168.1.0/24 directly connected
S 10.0.0.0/24 via 192.168.1.2
S* 0.0.0.0/0 via 192.168.1.1
```

---

# 6. Troubleshooting Commands

These commands are **very important in CCNA and interviews**.

## Check Interface Status

```
show ip interface brief
```

---

## Check Routing Table

```
show ip route
```

---

## Check MAC Address Table

```
show mac address-table
```

---

## Check ARP Table

```
show arp
```

---

## Test Connectivity

### Ping

```
ping 192.168.1.10
```

Used to check if a device is reachable.

---

### Traceroute

```
traceroute 8.8.8.8
```

Shows **path packets take to destination**.

---

# 7. Common Network Problems

## 1. Interface Shutdown

Problem:

```
Interface down
```

Fix:

```
no shutdown
```

---

## 2. Wrong IP Address

Example:

```
PC → 192.168.1.10
Router → 192.168.2.1
```

Different networks → communication fails.

---

## 3. Wrong Subnet Mask

Incorrect mask may cause routing problems.

Example:

```
255.255.255.0 vs 255.255.0.0
```

---

## 4. Missing Default Gateway

Without gateway, device **cannot reach other networks**.

---

## 5. VLAN Misconfiguration

Devices in different VLANs cannot communicate without routing.

---

# 8. Basic Troubleshooting Method

Network engineers usually follow this process:

```
1. Identify the problem
2. Gather information
3. Check physical connections
4. Check IP configuration
5. Test connectivity (ping)
6. Check routing table
7. Fix configuration
```

---

# 9. Important Interview Questions

## Q1. How do you check interface status?

Answer:

```
show ip interface brief
```

---

## Q2. How do you check routing table?

```
show ip route
```

---

## Q3. How do you test connectivity between devices?

```
ping
```

---

## Q4. What command shows MAC address table?

```
show mac address-table
```

---

## Q5. What command enables a router interface?

```
no shutdown
```

---

## Q6. What command shows ARP entries?

```
show arp
```

---

## Q7. What is the difference between ping and traceroute?

Ping → tests connectivity  
Traceroute → shows the path packets take

---

# Quick Revision Commands

```
show ip interface brief
show ip route
show arp
show mac address-table
ping
traceroute
```

---

# One Line Summary

```
Configuration → setting up router/switch
Troubleshooting → finding and fixing network problems
```
