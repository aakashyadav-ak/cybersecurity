ACL is a network security filter - like a security guard that checks traffic and decides: PERMIT or DENY
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

| Purpose                  | Example                          |
| :----------------------- | :------------------------------- |
| **Security**             | Block hackers/unwanted traffic   |
| **Traffic Control**      | Limit who can access servers     |
| **Bandwidth Management** | Restrict certain applications    |
| **NAT**                  | Identify traffic for translation |
| **VPN**                  | Define interesting traffic       |
| **QoS**                  | Classify traffic for priority    |

### Types of ACL 
```
┌─────────────────────────────────────────────────────────────────┐
│                    STANDARD ACL                                 │
├─────────────────────────────────────────────────────────────────┤
│  • Number: 1-99                                  │
│  • Filters by: SOURCE IP only                                   │
│  • Simple but less precise                                      │
│  • Place: CLOSE TO DESTINATION                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    EXTENDED ACL                                 │
├─────────────────────────────────────────────────────────────────┤
│  • Number: 100-199                                 │
│  • Filters by: Source IP, Dest IP, Protocol, Ports             │
│  • More precise control                                         │
│  • Place: CLOSE TO SOURCE                                       │
└─────────────────────────────────────────────────────────────────┘
```