### What is Active Directory?
Active Directory (AD) = Microsoft's centralized database for managing users, computers, and resources in a Windows network

**Active Directory is a Microsoft system used to manage:**
- users
- computers
- groups
- passwords
- policies
inside an organization network.

**Without AD (Small network):**
```
Each computer has its own user accounts
    ↓
User needs account on EVERY computer
    ↓
Passwords stored locally on each machine
    ↓
Nightmare to manage!
```

**With AD (Enterprise network):**
```
Central database of all users
    ↓
One account works everywhere
    ↓
Single sign-on (SSO)
    ↓
Easy centralized management
```

```
┌─────────────────────────────────────────────────────────────────┐
│                    ACTIVE DIRECTORY OVERVIEW                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                     (Enterprise)                        │   │
│   │  ┌─────────────────────────────────────────────────┐    │   │
│   │  │              DOMAIN: corp.local                 │    │   │
│   │  │                                                 │    │   │
│   │  │   ┌─────────┐  ┌─────────┐  ┌─────────┐         │    │   │
│   │  │   │   DC01  │  │   DC02  │  │  Backup │         │    │   │
│   │  │   │ (PDC)   │◄─┤(Replica)│  │   DC    │         │    │   │
│   │  │   └────┬────┘  └────┬────┘  └─────────┘         │    │   │
│   │  │        │            │                           │    │   │
│   │  │   ┌────┴────────────┴────┐                      │    │   │
│   │  │   │    LDAP/Kerberos     │                      │    │   │
│   │  │   └──────────┬───────────┘                      │    │   │
│   │  │              │                                  │    │   │
│   │  │   ┌──────────┴───────────┐                      │    │   │
│   │  │   │                      │                      │    │   │
│   │  │ ┌─┴──┐ ┌────┐ ┌────┐ ┌──┴─┐                     │    │   │
│   │  │ │User│ │User│ │Srv │ │Wks │  ...                │    │   │
│   │  │ └────┘ └────┘ └────┘ └────┘                     │    │   │
│   │  └─────────────────────────────────────────────---─┘    │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   Key Features:                                                 │
│   • Centralized Authentication    • Group Policy Management     │
│   • Single Sign-On (SSO)          • DNS Integration             │
│   • Resource Access Control       • Certificate Services        │
└─────────────────────────────────────────────────────────────────┘
```


### What AD Manages
| Resource       | Description           | Example                           |
| -------------- | --------------------- | --------------------------------- |
| Users          | Employee accounts     | john.doe, admin, service accounts |
| Computers      | Workstations, servers | DESKTOP-01, WEB-SERVER            |
| Groups         | Collections of users  | IT Team, Finance, Admins          |
| Printers       | Network printers      | Floor2-Printer, HR-Printer        |
| Shared Folders | File shares           | \\server\documents                |
| Policies       | Rules and settings    | Password policy, login hours      |
### AD Environment
```
Company Network (domain.local)
├── Domain Controller (DC)
│   └── Stores all AD data
│
├── Users
│   ├── john.doe (Marketing)
│   ├── admin (IT Admin)
│   └── service_sql (SQL Service)
│
├── Computers
│   ├── DESKTOP-JOHN (John's PC)
│   ├── WEB-SERVER (Web Server)
│   └── DC01 (Domain Controller)
│
└── Organizational Units (OUs)
    ├── Marketing OU
    ├── IT OU
    └── Servers OU
```

### Why attacker target AD
```
Compromise AD = Compromise Entire Network

If you control AD, you control:
├── ALL user accounts
├── ALL computers
├── ALL permissions
├── ALL resources
└── ENTIRE domain
```

### common Attacking phase
1. Gain initial foothold (phishing, exploit)
        ↓
2. Enumerate Active Directory
        ↓
3. Escalate privileges (become admin)
        ↓
4. Move laterally (access other systems)
        ↓
5. Compromise Domain Controller
        ↓
6. GAME OVER - Full domain control

## ==Common AD attack==

- Kerberoasting - 30% of breaches
- Pass-the-Hash - 25% of breaches
- Golden Ticket - 15% of breaches
- DCSync - 10% of breaches
- Credential Dumping - 20% of breaches


___ 

# 02: Basics of Active Directory (AD)

#### 1) Domain
A network of users + computers managed centrally.

Example:
- `company.local`

#### 2) Domain Controller (DC)
The main server that controls authentication.

- Stores AD database
- Handles logins

#### 3) Users
Employee accounts.

Example:
- `ak`
- `hr01`
- `itadmin`

#### 4) Computers
Machines joined to the domain.

Example:
- `WIN10-01`
- `HR-PC`

#### 5) Groups
Collection of users.

Examples:
- Domain Admins (highest)
- IT Support
- HR Team

#### 6) Group Policy (GPO)
Rules applied across domain.

Examples:
- password policy
- firewall settings
- software deployment

---