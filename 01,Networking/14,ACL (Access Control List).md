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

# Access Control Lists (ACLs)
## Standard ACL
```
┌─────────────────────────────────────────────────────────────┐
│                    STANDARD ACL                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Standard ACL:                                               │
│  • Numbers 1-99 or 1300-1999                                 │
│  • Filters based on SOURCE IP only                           │
│  • Apply CLOSE to destination                                │
│                                                              │
│  NUMBERED STANDARD ACL:                                      │
│  Router(config)# access-list 10 deny 192.168.1.0 0.0.0.255  │
│  Router(config)# access-list 10 permit any                   │
│  Router(config)# interface GigabitEthernet0/1                │
│  Router(config-if)# ip access-group 10 out                   │
│                                                              │
│  NAMED STANDARD ACL:                                         │
│  Router(config)# ip access-list standard BLOCK-SALES         │
│  Router(config-std-nacl)# deny 192.168.1.0 0.0.0.255        │
│  Router(config-std-nacl)# permit any                         │
│  Router(config-std-nacl)# exit                               │
│  Router(config)# interface GigabitEthernet0/1                │
│  Router(config-if)# ip access-group BLOCK-SALES out          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Extended ACL
```
┌─────────────────────────────────────────────────────────────┐
│                    EXTENDED ACL                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Extended ACL:                                               │
│  • Numbers 100-199 or 2000-2699                              │
│  • Filters based on: Source IP, Dest IP, Protocol, Port     │
│  • Apply CLOSE to source                                     │
│                                                              │
│  SYNTAX:                                                     │
│  access-list [number] [permit|deny] [protocol]               │
│              [source] [source-wildcard]                      │
│              [destination] [dest-wildcard]                   │
│              [operator port] [options]                       │
│                                                              │
│  EXAMPLES:                                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ! Deny HTTP from 10.0.0.0/24 to 192.168.1.100       │   │
│  │ access-list 100 deny tcp 10.0.0.0 0.0.0.255         │   │
│  │              host 192.168.1.100 eq 80               │   │
│  │                                                      │   │
│  │ ! Permit HTTPS from any to web servers              │   │
│  │ access-list 100 permit tcp any 192.168.1.0 0.0.0.255│   │
│  │              eq 443                                  │   │
│  │                                                      │   │
│  │ ! Deny ping (ICMP) from 10.1.1.0/24 to anywhere     │   │
│  │ access-list 100 deny icmp 10.1.1.0 0.0.0.255 any    │   │
│  │                                                      │   │
│  │ ! Permit everything else                             │   │
│  │ access-list 100 permit ip any any                    │   │
│  │                                                      │   │
│  │ ! Apply to interface                                 │   │
│  │ interface GigabitEthernet0/0                         │   │
│  │ ip access-group 100 in                               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```