==ACL is a set of rules used to permit or deny network traffic based on IP, port, or protocol.==

```
                    ┌─────────────┐
   Traffic ────────►│    ACL      │────────► Allowed Traffic
   (Packets)        │  (Filter)   │
                    └──────┬──────┘
                           │
                           ▼
                      Blocked Traffic
                         (Denied)
```

### Common Uses of ACLs / Traffic Filtering
- Control traffic flow
- Improve security
- Filter unwanted traffic

| Purpose                  | Example                          |
| :----------------------- | :------------------------------- |
| **Security**             | Block hackers/unwanted traffic   |
| **Traffic Control**      | Limit who can access servers     |
| **Bandwidth Management** | Restrict certain applications    |
| **NAT**                  | Identify traffic for translation |
| **VPN**                  | Define interesting traffic       |
| **QoS**                  | Classify traffic for priority    |

### Types of ACL 
## Standard ACL 
==Filters traffic based on source IP only==

**Place:** CLOSE TO DESTINATION Router.
## Extended ACL
Filters traffic based on Source IP, Destination IP, Port number, Protocol (TCP/UDP/ICMP)

**Place:** CLOSE TO SOURCE  Router.

**ACL ID numbers used to identify ACL type**
- 1-99 = Standard ACL 
- 100-199 Extended ACL
- ```
┌─────────────────────────────────────────────────────────────────┐
│                    STANDARD ACL                                 │
├─────────────────────────────────────────────────────────────────┤
│  • Number: 1-99                                                 │
│  • Filters by: SOURCE IP only                                   │
│  • Simple but less precise                                      │
│  • Place: CLOSE TO DESTINATION                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    EXTENDED ACL                                 │
├─────────────────────────────────────────────────────────────────┤
│  • Number: 100-199                                              │
│  • Filters by: Source IP, Dest IP, Protocol, Ports              │
│  • More precise control                                         │
│  • Place: CLOSE TO SOURCE                                       │
└─────────────────────────────────────────────────────────────────┘
```


_________________



# Port Security 
==Port security is a feature used to restrict which devices can connect to a switch port using MAC address==

**Purpose**
- Prevent unauthorized devices
- Improve LAN security

```
Switch Port → Check MAC → Allow / Block
```