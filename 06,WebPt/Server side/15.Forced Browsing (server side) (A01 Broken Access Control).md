- Accessing pages/resources that exist but aren't linked in the UI, but we can access them by directly entering URLs.

- Forced Browsing is accessing restricted or hidden pages by guessing/Brute Forcing the URL directly, rather than clicking a link provided by the website.

```
┌─────────────────────────────────────────────────────────────────┐
│                      FORCED BROWSING                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Application has hidden/unlinked pages that attacker           │
│   discovers by guessing or brute-forcing URLs                   │
│                                                                 │
│                                                                 │
│   ┌──────────────────────────────────────────┐                  │
│   │            WEBSITE                       │                  │
│   │                                          │                  │
│   │   Visible Links:                         │                  │
│   │   ├── /home                              │                  │
│   │   ├── /about                             │                  │
│   │   ├── /contact                           │                  │
│   │   └── /login                             │                  │
│   │                                          │                  │
│   │   Hidden (But Accessible!):              │                  │
│   │   ├── /admin           ← Attacker finds! │                  │
│   │   ├── /backup          ← Attacker finds! │                  │
│   │   └── /config          ← Attacker finds! │                  │
│   │                                          │                  │
│   └──────────────────────────────────────────┘                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Types of Forced Browsing
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FORCED BROWSING TYPES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. Admin/Management Pages                                                 │
│      ├── /admin                                                             │
│      ├── /administrator                                                     │
│      ├── /manage                                                            │
│      ├── /dashboard                                                         │
│      └── /control-panel                                                     │
│                                                                             │
│   2. Backup & Configuration Files                                           │
│      ├── /backup/                                                           │
│      ├── /backup.zip                                                        │
│      ├── /config.php.bak                                                    │
│      ├── /database.sql                                                      │
│      └── /.env                                                              │
│                                                                             │
│   3. Debug & Development Endpoints                                          │
│      ├── /debug                                                             │
│      ├── /test                                                              │
│      ├── /phpinfo.php                                                       │
│      ├── /console                                                           │
│      └── /actuator (Spring Boot)                                            │
│                                                                             │
│   4. API Endpoints                                                          │
│      ├── /api/v1/admin/users                                                │
│      ├── /api/internal/config                                               │
│      ├── /api/debug/logs                                                    │
│      └── /swagger-ui.html                                                   │
│                                                                             │
│   5. Source Code & Version Control                                          │
│      ├── /.git/                                                             │
│      ├── /.svn/                                                             │
│      ├── /.hg/                                                              │
│      └── /src/                                                              │
│                                                                             │
│   6. Log Files                                                              │
│      ├── /logs/                                                             │
│      ├── /error.log                                                         │
│      ├── /access.log                                                        │
│      └── /debug.log                                                         │
│                                                                             │
│   7. Default Installation Files                                             │
│      ├── /readme.txt                                                        │
│      ├── /INSTALL.txt                                                       │
│      ├── /CHANGELOG.md                                                      │
│      └── /license.txt                                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Example 1: Finding Admin Panel
```
# Attacker tries common admin URLs
GET /admin HTTP/1.1
Host: target.com

# Response
HTTP/1.1 200 OK

<html>
  <title>Admin Dashboard</title>
  <h1>Welcome Administrator</h1>
  ...
</html>

# No authentication required! VULNERABLE!
```

### Testing Tools
```
┌─────────────────────────────────────────────────────────────────┐
│                    FORCED BROWSING TOOLS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. Gobuster                                                   │
│      gobuster dir -u https://target.com -w wordlist.txt         │
│                                                                 │
│   2. Dirb                                                       │
│      dirb https://target.com /path/to/wordlist.txt              │
│                                                                 │
│   3. Dirsearch                                                  │
│      dirsearch -u https://target.com -w wordlist.txt            │
│                                                                 │
│   4. Ffuf                                                       │
│      ffuf -u https://target.com/FUZZ -w wordlist.txt            │
│                                                                 │
│   5. Feroxbuster                                                │
│      feroxbuster -u https://target.com -w wordlist.txt          │
│                                                                 │
│   6. Burp Suite (Intruder)                                      │
│      Use Sniper attack with directory wordlist                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

```
# Gobuster
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -t 50

# Ffuf (faster)
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,301,302

# Dirsearch
dirsearch -u https://target.com -e php,html,js,txt -t 50

# With extensions
gobuster dir -u https://target.com -w wordlist.txt -x php,txt,bak,sql,zip
```

**Wordlists**
```
# SecLists (Recommended)
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

# Dirb
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/big.txt

# Specific
/usr/share/seclists/Discovery/Web-Content/quickhits.txt
/usr/share/seclists/Discovery/Web-Content/SVNDigger/all.txt
```

```
┌─────────────────────────────────────────────────────────────────┐
│                  RESPONSE INTERPRETATION                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Status Code    │    Meaning                                   │
│   ──────────────────────────────────────────────────────────    │
│   200 OK         │    Resource exists and accessible            │
│   301/302        │    Redirect (follow it)                      │
│   401            │    Exists but requires authentication        │
│   403            │    Exists but forbidden (try bypass)         │
│   404            │    Does not exist                            │
│   500            │    Server error (might be interesting)       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Mitigations
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FORCED BROWSING MITIGATIONS                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. Implement Proper Access Control                                        │
│      ├── Authenticate all sensitive endpoints                               │
│      ├── Authorize before serving any resource                              │
│      └── Deny by default, allow explicitly                                  │
│                                                                             │
│   2. Remove Unnecessary Files                                               │
│      ├── Delete backup files from production                                │
│      ├── Remove debug/test endpoints                                        │
│      ├── Clean up installation files                                        │
│      └── Don't deploy .git/.svn folders                                     │
│                                                                             │
│   3. Disable Directory Listing                                              │
│      ├── Apache:  Options -Indexes                                          │
│      ├── Nginx:   autoindex off;                                            │
│      └── IIS:     Disable in Directory Browsing                             │
│                                                                             │
│   4. Use Proper File Permissions                                            │
│      ├── Restrict access to sensitive directories                           │
│      ├── Web server user shouldn't read everything                          │
│      └── Separate public and private files                                  │
│                                                                             │
│   5. Implement Rate Limiting                                                │
│      ├── Detect brute-force scanning                                        │
│      ├── Block suspicious IPs                                               │
│      └── Alert on enumeration attempts                                      │
│                                                                             │
│   6. Web Application Firewall (WAF)                                         │
│      ├── Block known attack patterns                                        │
│      ├── Detect scanning tools                                              │
│      └── Virtual patching                                                   │
│                                                                             │
│   7. Security Headers                                                       │
│      ├── X-Content-Type-Options: nosniff                                    │
│      └── Proper Content-Type for all responses                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```