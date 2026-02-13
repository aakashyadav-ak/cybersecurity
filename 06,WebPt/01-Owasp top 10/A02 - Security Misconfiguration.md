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