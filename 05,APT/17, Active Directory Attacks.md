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

#### 7) Forest
Collection of one or more domains sharing a common schema

**example:**
```
Forest: company.com
├── Domain: sales.company.com
├── Domain: marketing.company.com
└── Domain: it.company.com
```

#### 8) Organizational Unit (OU)
Container for organizing users, groups, computers

**exapmle:**
```
company.local
├── OU=IT
├── OU=HR
└── OU=Servers
```

___ 

## Architecture
```
Active Directory Structure:
├── Forest (Highest level)
│   └── Tree (Collection of domains)
│       └── Domain (company.local)
│           ├── Organizational Units (OUs)
│           │   ├── Users
│           │   ├── Computers
│           │   └── Groups
│           └── Objects (User accounts, computers, etc.)
```

```
┌─────────────────────────────────────────────────────────────────┐
│                    ACTIVE DIRECTORY OVERVIEW                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                 Forest (Enterprise)                     │   │
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


## AD Objects
#### 1. Users
What: Accounts representing people or services

**Types:**
**Regular Users - Employees (john.doe, jane.smith)**
**Service Accounts - Used by applications (sql_service, web_app)**
**Admin Accounts - Privileged users (administrator, domain_admin)**

**Attributes:**
```
Username: john.doe
Display Name: John Doe
Email: john.doe@company.com
Groups: Domain Users, IT Team
Password: [Encrypted]
Login Script: login.bat
```

#### 2. Computers
What: Workstations and servers joined to domain

**Examples:**
```
DESKTOP-JOHN$     (John's workstation)
WEB-SERVER01$     (Web server)
DC01$             (Domain Controller)
```
**Note:** Computer accounts end with $ symbol

#### 3. Groups
What: Collections of users for easier permission management

**Types:**

| Type                | Scope              | Use Case                           |
| ------------------- | ------------------ | ---------------------------------- |
| Security Groups     | Assign permissions | "IT Admins can access servers"     |
| Distribution Groups | Email lists        | "All employees receive newsletter" |

**Common Built-in Groups:**
- Domain Admins - Full control over domain
- Enterprise Admins - Full control over forest
- Domain Users - All regular users
- Domain Computers - All domain computers


#### 4. Organizational Units (OUs)
What: Containers to organize AD objects

**Purpose:**
- Apply Group Policies
- Delegate administrative control
- Logical organization

**Example Structure:**
```
company.local
├── OU=Employees
│   ├── OU=IT
│   ├── OU=HR
│   └── OU=Finance
├── OU=Computers
│   ├── OU=Workstations
│   └── OU=Servers
└── OU=Service Accounts
```

___
## Authentication Protocols

### 1. Kerberos (Primary)
Ticket-based authentication protocol

**How it Works:**
```
Step 1: User logs in
    ↓
Step 2: Request Ticket Granting Ticket (TGT) from DC
    ↓
Step 3: DC verifies credentials and issues TGT
    ↓
Step 4: User requests Service Ticket using TGT
    ↓
Step 5: Access resource with Service Ticket
```

**Key Concepts:**

- TGT (Ticket Granting Ticket) - Proves you're authenticated
- Service Ticket - Access to specific service
- KDC (Key Distribution Center) - Issues tickets (runs on DC)
- Default Port: 88

### 2. NTLM (Legacy)
Challenge-response authentication protocol

**Used When:**
- Kerberos unavailable
- IP address used instead of hostname
- Legacy systems

**Security:** Weaker than Kerberos, vulnerable to Pass-the-Hash


### 3. LDAP (Lightweight Directory Access Protocol)
Protocol for querying and modifying AD

**Uses:**
- Search for users/computers
- Read object attributes
- Modify AD objects

**Default Ports:**
389 - LDAP
636 - LDAPS (Secure)
3268 - Global Catalog


___

## Group Policy (GPO)
Set of rules controlling user and computer settings

**Common Policies:**
- Password requirements
- Software installation
- Desktop wallpaper
- Security settings
- Login scripts


**Example GPO:**
```
Policy: "Strong Password Policy"
├── Minimum length: 12 characters
├── Complexity: Required
├── Maximum age: 90 days
├── History: Remember 10 passwords
└── Lockout: 5 failed attempts
```


___

# 03: Enumeration of Active Directory (AD)
AD Enumeration = Process of gathering information about Active Directory environment
```
Goal: Discover
├── Users (Who exists?)
├── Computers (What systems?)
├── Groups (Who has permissions?)
├── Permissions (Who can do what?)
├── Trusts (What domains are connected?)
└── Vulnerabilities (Where to attack?)
```

### Enumeration Tools

| Category         | Tools                             | Use Case                   |
| ---------------- | --------------------------------- | -------------------------- |
| Windows Built-in | net, dsquery, PowerShell          | Stealthy, always available |
| Sysinternals     | AdExplorer, AdInsight             | GUI-based enumeration      |
| PowerShell       | PowerView, ADModule               | Powerful scripting         |
| Linux            | ldapsearch, enum4linux, rpcclient | From Kali/attacker machine |
| Automated        | BloodHound, SharpHound            | Visual attack paths        |


##  Windows Built-in Commands
#### 1. NET Commands

**Enumerate Users:**
```
# List all domain users
net user /domain

# Get specific user info
net user john.doe /domain

# Find all user accounts
net user /domain | findstr /i "user"
```

**Enumerate Groups:**
```
# List all domain groups
net group /domain

# List members of Domain Admins
net group "Domain Admins" /domain

# List all local administrators
net localgroup administrators
```


**Enumerate Computers:**
```
# List domain controllers
net group "Domain Controllers" /domain

# List all computers
net group "Domain Computers" /domain
```

#### 2. PowerView (PowerSploit)
**Domain:**
```
# Get current domain
Get-Domain

# Get domain SID
Get-DomainSID

# Get domain policy
Get-DomainPolicy

# Get domain controllers
Get-DomainController
```

**User Enumeration:**
```
# Get all users
Get-DomainUser

# Get specific user
Get-DomainUser -Identity john.doe

# Get user properties
Get-DomainUser -Properties samaccountname, memberof

# Find admin users
Get-DomainUser -AdminCount

# Find users with SPN (Kerberoastable)
Get-DomainUser -SPN
```


##  Linux-Based Enumeration
#### 1. ldapsearch
```bash
# Anonymous bind (if allowed)
ldapsearch -x -H ldap://10.10.10.10 -b "DC=company,DC=local"

# With credentials
ldapsearch -x -H ldap://10.10.10.10 -D "CN=john.doe,CN=Users,DC=company,DC=local" -w 'password' -b "DC=company,DC=local"

# Get all users
ldapsearch -x -H ldap://10.10.10.10 -D "user@company.local" -w 'password' -b "DC=company,DC=local" "(objectClass=user)"

# Get all computers
ldapsearch -x -H ldap://10.10.10.10 -D "user@company.local" -w 'password' -b "DC=company,DC=local" "(objectClass=computer)"

# Get specific attributes
ldapsearch -x -H ldap://10.10.10.10 -D "user@company.local" -w 'password' -b "DC=company,DC=local" "(objectClass=user)" sAMAccountName userPrincipalName

# Find users with SPN
ldapsearch -x -H ldap://10.10.10.10 -D "user@company.local" -w 'password' -b "DC=company,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" servicePrincipalName
```

#### 2. enum4linux
Basic Usage:

```bash
# Full enumeration
enum4linux -a 10.10.10.10

# User enumeration
enum4linux -U 10.10.10.10

# Group enumeration
enum4linux -G 10.10.10.10

# Share enumeration
enum4linux -S 10.10.10.10

# Password policy
enum4linux -P 10.10.10.10

# With credentials
enum4linux -u "user" -p "password" -a 10.10.10.10
```

## BloodHound - Visual AD Enumeration
BloodHound = Tool that visualizes attack paths in Active Directory

```
Purpose:
├── Maps relationships between AD objects
├── Finds shortest path to Domain Admin
├── Identifies misconfigurations
└── Visual graph of attack paths
```

```bash
# Install Neo4j (graph database)
sudo apt install neo4j

# Install BloodHound
sudo apt install bloodhound

# Start Neo4j
sudo neo4j console

# Access Neo4j browser
http://localhost:7474
# Default creds: neo4j/neo4j (change on first login)

# Start BloodHound
bloodhound
```