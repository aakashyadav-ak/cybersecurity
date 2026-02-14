Security Misconfiguration happens when the application, server, or cloud environment is **not securely configured**, leaving **unnecessary features exposed**.

“Security misconfiguration occurs when default or insecure settings are used, such as debug mode, directory listing, default credentials, open cloud storage, or missing security headers.”

**Security misconfiguration can occur at:**

### 1) Application Level
- Debug mode enabled
- Verbose errors
- Weak CORS
- Misconfigured authentication settings

### 2) Web Server Level (Apache/Nginx/IIS)
- Directory listing
- Exposed server status pages
- Insecure HTTP methods

### 3) OS / Services Level
- Exposed ports
- Unpatched services
- Default credentials

### 4) Cloud / Infrastructure Level
- Public S3 buckets
- Open storage containers
- Exposed admin consoles

### 5) Security Headers Level
- Missing or weak headers

---

## 1- Debug Mode Enabled / Verbose Errors
When developers build an app, they use debug mode to find bugs. But if they forget to turn it OFF before going live attackers see everything.

### Verbose Error Example:
```
YOU TYPE: ' (single quote in login)

❌ VULNERABLE RESPONSE (Verbose Error):
─────────────────────────────────────────
Fatal error: Uncaught PDOException: 
SQLSTATE[42000]: Syntax error in SQL query

File: /var/www/html/includes/db.php
Line: 42
Database: myapp_production
User: db_admin
Password: SuperSecret123!

PHP Version: 8.1.12
MySQL Version: 8.0.32
Server: Apache/2.4.54 (Ubuntu)

Stack Trace:
#0 /var/www/html/login.php(15)
#1 /var/www/html/includes/auth.php(28)
─────────────────────────────────────────

What attacker learned:
→ Database name: myapp_production
→ DB Username: db_admin
→ DB Password: SuperSecret123!     😱
→ File paths: /var/www/html/
→ PHP version: 8.1.12
→ Server: Apache on Ubuntu
→ Code structure: login.php → auth.php → db.php
```

### Testing
#### Method 1: Trigger Errors Manually
```
Step 1: Go to login page
Step 2: Type ' (single quote) in username
Step 3: Type random password
Step 4: Click Login
Step 5: See the response

If you see → "Something went wrong"     → ✅ Safe
If you see → Stack trace, file paths     → 🚨 Vulnerable!
```

#### Method 2: Access Non-Existent Pages
```
Try these URLs in browser:

http://target.com/pagenotexist123
http://target.com/admin/../../../etc/passwd
http://target.com/test.php

If you see → Nice custom "404 Page Not Found"    → ✅ Safe
If you see → Detailed error with server info      → 🚨 Vulnerable!
```
#### Method 3: Using Burp Suite
```
Step 1: Open Burp Suite → Proxy → Intercept
Step 2: Capture any request
Step 3: Modify the request:
        → Change Content-Type to something wrong
        → Remove required parameters
        → Send empty body
        → Add special characters
Step 4: Check response for error details
```


## 2- Directory Listing Enabled
When you visit a folder on a website and the server shows you ALL files inside that folder — like opening someone's file cabinet.

**example:**
```
Browser: http://target.com/uploads/

┌──────────────────────────────────────────────┐
│  Index of /uploads/                           │
│                                               │
│  [ICO] Name                 Size    Modified  │
│  ──────────────────────────────────────────── │
│  [DIR] Parent Directory      -                │
│  [   ] backup_db.sql        25MB   2024-01-15 │  ← Full database! 😱
│  [   ] config.php.bak       4KB    2024-02-20 │  ← Config with passwords!
│  [   ] employee_data.xlsx   12MB   2024-03-10 │  ← Personal data!
│  [   ] id_rsa               2KB    2024-04-05 │  ← SSH private key!
│  [   ] passwords.txt        1KB    2024-05-12 │  ← Passwords!
│  [   ] creditcards.csv      8MB    2024-06-01 │  ← Credit card data! 😱
│  [IMG] admin_screenshot.png 500KB  2024-07-20 │  ← Internal screenshots
└──────────────────────────────────────────────┘

Attacker can DOWNLOAD all these files just by clicking!
```

## Testing

#### Using Tools
```
# dirb — Simple directory scanner
dirb http://target.com

# gobuster — Faster scanner
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# dirsearch — Python based
dirsearch -u http://target.com

# Nikto — Web server scanner (also checks directory listing)
nikto -h http://target.com
```

####  Using Burp Suite
```
Step 1: Open Burp Suite
Step 2: Browse the website through Burp Proxy
Step 3: Go to Target → Site Map
Step 4: Look at all discovered directories
Step 5: Right-click → Open in Browser
Step 6: Check if directory listing is shown
```

## 3- Default Credentials
Applications, devices, databases, admin panels shipped with default usernames and passwords that are never changed.

 Admin panel uses default username/password.
**Examples**
- `admin:admin`
- `root:toor`
- `test:test`

### Testing:
Step 1: Identify application/service (Wappalyzer, Nmap)
Step 2: Google: "APPLICATION_NAME default credentials"
Step 3: Try default creds on login page
Step 4: Check: `https://creds.fish/` or `https://default-password.info/`

Tools:
→ Hydra (brute force default creds)
→ Metasploit (auxiliary/scanner modules)
→ Nmap scripts (--script=http-default-accounts)


### Mitigation
- Change ALL default credentials before deployment
- Force password change on first login
- Use strong, unique passwords
- Use multi-factor authentication (MFA)

## 4-Unnecessary Services/Ports/Features
Running services, ports, or features that are not needed — increasing attack surface.

### testing
```bash
# Port Scanning
nmap -sV -p- target.com

# Common unnecessary ports found:
21    FTP          → Often anonymous login allowed
22    SSH          → Should be restricted by IP
23    Telnet       → Unencrypted! Should never be open
25    SMTP         → Open relay?
445   SMB          → EternalBlue, WannaCry
3306  MySQL        → Should not be public
5432  PostgreSQL   → Should not be public
6379  Redis        → Often no authentication!
8080  Tomcat       → Manager panel exposed?
9200  Elasticsearch→ Often no authentication!
27017 MongoDB      → Often no authentication!
```

**Unnecessary Features:**
→ Sample/test applications installed
→ Unused API endpoints active
→ Admin consoles accessible publicly
→ Unused HTTP methods enabled (PUT, DELETE, TRACE)
→ Unused plugins/modules loaded
→ FTP running when not needed
→ SNMP with default community strings

### mitigation
```
# Disable unnecessary services
sudo systemctl disable telnet
sudo systemctl disable ftp
sudo systemctl disable cups

# Close unnecessary ports (firewall)
sudo ufw default deny incoming
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from TRUSTED_IP to any port 22
sudo ufw enable

# Remove sample applications
rm -rf /var/www/html/examples/
rm -rf /opt/tomcat/webapps/examples/
rm -rf /opt/tomcat/webapps/docs/

# Principle of Least Functionality
# Only install what you NEED
# Only enable what you USE
```


## 5-Missing Security Headers
HTTP response headers that protect against attacks but are not configured.

### Testing
```bash
# Quick check
curl -I https://target.com

# Online tools
→ https://securityheaders.com
→ https://observatory.mozilla.org
```


Security Headers Checklist:
```
╔════════════════════════════════════════════════════════════════════╗
║ Header                          │ Purpose            │ Status     ║
╠════════════════════════════════════════════════════════════════════╣
║ Strict-Transport-Security       │ Force HTTPS        │ ❌ Missing ║
║ Content-Security-Policy         │ Prevent XSS        │ ❌ Missing ║
║ X-Content-Type-Options          │ Prevent MIME sniff  │ ❌ Missing ║
║ X-Frame-Options                 │ Prevent Clickjack  │ ❌ Missing ║
║ X-XSS-Protection                │ XSS filter         │ ❌ Missing ║
║ Referrer-Policy                 │ Control referrer    │ ❌ Missing ║
║ Permissions-Policy              │ Control features    │ ❌ Missing ║
║ Cache-Control                   │ Prevent caching     │ ❌ Missing ║
╚════════════════════════════════════════════════════════════════════╝
```

### Mitigation 
```
# ✅ Apache (.htaccess or httpd.conf)

# Force HTTPS
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Prevent XSS
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'"

# Prevent MIME sniffing
Header always set X-Content-Type-Options "nosniff"

# Prevent Clickjacking
Header always set X-Frame-Options "DENY"

# XSS Filter
Header always set X-XSS-Protection "1; mode=block"

# Referrer Policy
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions Policy
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"

# Remove Server version
ServerTokens Prod
Header unset Server
Header unset X-Powered-By
```