
# OWASP MOBILE TOP 10 (2024)
## M01:2024 - Improper Credential Usage
- [ ] Hardcoded API Keys in Source Code
- [ ] Hardcoded Passwords in Code
- [ ] Hardcoded Secrets in strings.xml/plist
- [ ] Credentials in BuildConfig Files
- [ ] API Keys in AndroidManifest.xml/Info.plist
- [ ] Secrets in Native Libraries (.so files)
- [ ] Credentials Logged in Logcat/Console
- [ ] Credentials in Crash Reports
- [ ] Shared Credentials Across Users
- [ ] Credentials in Memory (Runtime Analysis)
- [ ] Credentials in Clipboard
- [ ] OAuth Token Mishandling
- [ ] Firebase/AWS Keys Exposure
- [ ] Third-party SDK Credentials Exposure

## M02:2024 - Inadequate Supply Chain Security
- [ ] Outdated Libraries with Known CVEs
- [ ] Vulnerable Third-party SDKs
- [ ] Malicious Dependencies
- [ ] Unverified Library Sources
- [ ] Missing Integrity Verification
- [ ] Dependency Confusion Attacks
- [ ] Compromised SDK Updates
- [ ] Unsigned Libraries
- [ ] Typosquatting Libraries
- [ ] Abandoned/Unmaintained Libraries
- [ ] License Compliance Issues
- [ ] Transitive Dependency Vulnerabilities
- [ ] Debug SDKs in Production

## M03:2024 - Insecure Authentication/Authorization
### Authentication Flaws
- [ ] Weak Password Policy Acceptance
- [ ] No Account Lockout Mechanism
- [ ] Brute Force Attack Success
- [ ] Credential Stuffing Vulnerability
- [ ] Biometric Authentication Bypass
- [ ] Local Authentication Bypass
- [ ] Remember Me Token Weakness
- [ ] Insecure "Forgot Password" Flow
- [ ] SMS OTP Interception
- [ ] 2FA/MFA Bypass Techniques
- [ ] Session Token Predictability
- [ ] Session Not Invalidated on Logout
- [ ] Session Not Invalidated on Password Change
- [ ] Concurrent Session Issues
- [ ] Device Binding Bypass

### Authorization Flaws
- [ ] IDOR (Insecure Direct Object Reference)
- [ ] Horizontal Privilege Escalation
- [ ] Vertical Privilege Escalation
- [ ] Missing Function Level Access Control
- [ ] Role Manipulation
- [ ] API Authorization Bypass
- [ ] Client-Side Authorization Checks
- [ ] JWT Token Manipulation
- [ ] OAuth Scope Bypass
- [ ] Deep Link Authorization Bypass

## M04:2024 - Insufficient Input/Output Validation
### Injection Attacks
- [ ] SQL Injection in Local DB
- [ ] SQL Injection via API
- [ ] NoSQL Injection
- [ ] LDAP Injection
- [ ] XML Injection
- [ ] XPath Injection
- [ ] OS Command Injection
- [ ] Format String Vulnerabilities

### Client-Side Injection
- [ ] XSS in WebView (Reflected)
- [ ] XSS in WebView (Stored)
- [ ] XSS in WebView (DOM-based)
- [ ] JavaScript Interface Exploitation
- [ ] HTML Injection
- [ ] CSS Injection

### File-Based Attacks
- [ ] Path Traversal (Local Files)
- [ ] Local File Inclusion
- [ ] Zip Slip Vulnerability
- [ ] File Upload Vulnerabilities
- [ ] Content Provider Path Traversal

### Other Validation Issues
- [ ] Buffer Overflow
- [ ] Integer Overflow
- [ ] Input Length Bypass
- [ ] Special Character Bypass
- [ ] Unicode/Encoding Bypass
- [ ] Null Byte Injection

## M05:2024 - Insecure Communication
### TLS/SSL Issues
- [ ] HTTP Traffic (Cleartext)
- [ ] Mixed Content (HTTP + HTTPS)
- [ ] Weak TLS Versions (TLS 1.0/1.1)
- [ ] Weak Cipher Suites
- [ ] Invalid Certificate Acceptance
- [ ] Self-Signed Certificate Acceptance
- [ ] Hostname Verification Bypass
- [ ] Certificate Expiry Not Checked

### Certificate Pinning
- [ ] No Certificate Pinning
- [ ] Weak Pinning Implementation
- [ ] Certificate Pinning Bypass (Frida)
- [ ] Certificate Pinning Bypass (Objection)
- [ ] Backup Pin Exploitation

### Data in Transit
- [ ] Sensitive Data in URL Parameters
- [ ] Sensitive Data in HTTP Headers
- [ ] Credentials Sent Over HTTP
- [ ] Session Tokens Over HTTP
- [ ] PII Transmitted Unencrypted
- [ ] API Keys in Transit (Unprotected)

### Network Attacks
- [ ] Man-in-the-Middle (MITM) Success
- [ ] SSL Stripping Attack
- [ ] ARP Spoofing Vulnerability
- [ ] DNS Spoofing Vulnerability
- [ ] WebSocket Security Issues

## M06:2024 - Inadequate Privacy Controls
### Data Collection Issues
- [ ] Excessive Permissions Requested
- [ ] Unnecessary Data Collection
- [ ] Location Tracking Without Consent
- [ ] Contact Access Without Justification
- [ ] Camera/Microphone Abuse
- [ ] Device Identifiers Collection (IMEI/UDID)
- [ ] Advertising ID Misuse

### Data Exposure
- [ ] PII in Application Logs
- [ ] PII in Crash Reports
- [ ] PII Sent to Third-party Analytics
- [ ] User Data Shared Without Consent
- [ ] Clipboard Data Exposure
- [ ] Screenshot/Screen Recording Allowed
- [ ] Keyboard Cache Sensitive Data
- [ ] Pasteboard Persistence (iOS)

### Privacy Compliance
- [ ] Missing Privacy Policy
- [ ] Policy vs Behavior Mismatch
- [ ] No Data Deletion Option
- [ ] No Data Export Option
- [ ] Data Retention Issues
- [ ] Cross-border Data Transfer Issues
- [ ] Child Data Protection (COPPA)
- [ ] GDPR Compliance Issues

## M07:2024 - Insufficient Binary Protections
### Reverse Engineering
- [ ] No Code Obfuscation
- [ ] Readable Class/Method Names
- [ ] Decompilation Success (JADX/Hopper)
- [ ] String Encryption Missing
- [ ] Resource Encryption Missing
- [ ] Native Code Not Protected
- [ ] Debug Symbols Present

### Runtime Protection
- [ ] No Root/Jailbreak Detection
- [ ] Root Detection Bypass (Frida)
- [ ] Root Detection Bypass (Magisk Hide)
- [ ] No Emulator Detection
- [ ] Emulator Detection Bypass
- [ ] No Debugger Detection
- [ ] Debugger Attach Success
- [ ] No Frida/Xposed Detection
- [ ] Hooking Framework Success
- [ ] Memory Dump Success

### Integrity Protection
- [ ] No Tamper Detection
- [ ] APK Modification Success
- [ ] Repackaging Success
- [ ] Signature Verification Bypass
- [ ] Checksum Verification Missing
- [ ] Dynamic Loading Exploitation

## M08:2024 - Security Misconfiguration
### Android Specific
- [ ] android:debuggable="true"
- [ ] android:allowBackup="true"
- [ ] android:usesCleartextTraffic="true"
- [ ] Exported Activities (Unprotected)
- [ ] Exported Services (Unprotected)
- [ ] Exported Broadcast Receivers
- [ ] Exported Content Providers
- [ ] Intent Filter Vulnerabilities
- [ ] Pending Intent Vulnerabilities
- [ ] Task Hijacking Vulnerability
- [ ] Fragment Injection
- [ ] WebView JavaScript Enabled (Unsafe)
- [ ] WebView File Access Enabled
- [ ] WebView Universal Access Enabled
- [ ] Insecure Network Security Config

### iOS Specific
- [ ] ATS Disabled Entirely
- [ ] ATS Exceptions Too Broad
- [ ] Insecure URL Schemes
- [ ] Keychain Accessibility Issues
- [ ] Background Fetch Exposure
- [ ] Extension Data Sharing Issues
- [ ] Pasteboard Sharing Enabled
- [ ] Third-party Keyboard Allowed

### General Misconfigurations
- [ ] Debug Mode in Production
- [ ] Verbose Error Messages
- [ ] Default Credentials
- [ ] Test Accounts in Production
- [ ] Development Endpoints Exposed
- [ ] Unnecessary Features Enabled
- [ ] Insecure Deep Link Handling
- [ ] Custom URL Scheme Hijacking

## M09:2024 - Insecure Data Storage
### Shared Preferences / NSUserDefaults
- [ ] Passwords in SharedPreferences
- [ ] Tokens in SharedPreferences
- [ ] PII in SharedPreferences
- [ ] Sensitive Data in NSUserDefaults
- [ ] MODE_WORLD_READABLE Files
- [ ] MODE_WORLD_WRITEABLE Files

### Database Storage
- [x] Unencrypted SQLite Database
- [x] Sensitive Data in SQLite
- [ ] Realm Database Unencrypted
- [ ] Couchbase Lite Unencrypted
- [ ] Firebase Local Cache Exposure

### File Storage
- [x] Sensitive Data in External Storage
- [ ] Sensitive Data in Cache Files
- [ ] Sensitive Data in Temp Files
- [ ] Log Files Contain Sensitive Data
- [ ] Backup Files Exposure
- [ ] WebView Cache Sensitive Data
- [ ] Cookie Storage Issues
- [ ] Screenshot Caching (Recent Apps)

### Secure Storage Issues
- [ ] Keystore/Keychain Not Used
- [ ] Weak Keystore Protection
- [ ] Extractable Keychain Items
- [ ] Hardware Security Module Not Used
- [ ] Biometric-Protected Keys Bypass

### Memory Issues
- [ ] Sensitive Data in Memory Dumps
- [ ] Credentials in Process Memory
- [ ] Memory Not Cleared After Use
- [ ] Swap File Data Exposure

## M10:2024 - Insufficient Cryptography
### Weak Algorithms
- [ ] MD5 Hashing Used
- [ ] SHA1 Hashing Used
- [ ] DES Encryption Used
- [ ] 3DES Encryption Used
- [ ] RC4 Encryption Used
- [ ] ECB Mode Used
- [ ] Weak Key Sizes (<2048 RSA, <256 AES)
- [ ] Broken Random Number Generator

### Key Management
- [ ] Hardcoded Encryption Keys
- [ ] Keys in Source Code
- [ ] Keys in Shared Preferences
- [ ] Keys in Strings Resources
- [ ] Predictable Key Generation
- [ ] Same Key for Multiple Purposes
- [ ] No Key Rotation
- [ ] Keys Transmitted in Cleartext

### Implementation Issues
- [ ] Custom Cryptography Implementation
- [ ] Improper IV/Nonce Usage
- [ ] IV/Nonce Reuse
- [ ] Missing Authentication (MAC)
- [ ] Padding Oracle Vulnerability
- [ ] Timing Side-Channel Attack
- [ ] Encryption Without Integrity

### Certificate Issues
- [ ] Self-Signed Certificates Accepted
- [ ] Certificate Validation Disabled
- [ ] Expired Certificates Accepted
- [ ] Wrong Host Certificates Accepted

---
```
┌─────────────────────────────────────────────────────────────┐
│  M1: IMPROPER CREDENTIAL USAGE                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     App handles passwords/keys/tokens incorrectly           │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Hardcoded API keys in app code                        │
│     • Storing passwords in plain text                       │
│     • Using same credentials for all users                  │
│     • Credentials visible in app logs                       │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Decompile app with JADX/APKTool                      │
│     2. Search for: "password", "api_key", "secret"          │
│     3. Check AndroidManifest.xml for exposed data           │
│     4. Review log files for credentials                     │
│                                                             │
│  ✅ PROPER FIX:                                             │
│     • Use secure key storage (Keystore/Keychain)            │
│     • Never hardcode credentials                            │
│     • Use environment variables for secrets                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M2: INADEQUATE SUPPLY CHAIN SECURITY                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     Using untrusted or outdated third-party libraries       │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Outdated libraries with known vulnerabilities         │
│     • Unverified SDKs from unknown sources                  │
│     • Malicious code hidden in dependencies                 │
│     • Compromised build tools or CI/CD pipeline             │
│     • Using libraries without checking their source         │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. Developer adds popular-looking library               │
│     2. Library has hidden code that steals data             │
│     3. App gets published with malicious library            │
│     4. User data gets sent to attacker's server             │
│     5. Thousands of users compromised!                      │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. List all dependencies in your project                │
│     2. Check each library's last update date                │
│     3. Search for CVEs (known vulnerabilities)              │
│     4. Verify library source and maintainer                 │
│     5. Use automated scanning tools                         │
│                                                             │
│  ⚠️ VULNERABLE SETUP:                                       │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // build.gradle - Dangerous!                    │     │
│     │ dependencies {                                  │     │
│     │     implementation 'unknown:library:1.0.0'      │     │
│     │     implementation 'old-lib:2.0.0' // 5 yrs old │     │
│     │     implementation 'http://shady-site.com/lib'  │     │
│     │ }                                               │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE SETUP:                                           │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // build.gradle - Safe!                         │     │
│     │ dependencies {                                  │     │
│     │     implementation 'com.google:verified:3.2.1'  │     │
│     │     // Pinned version, verified publisher       │     │
│     │     // Checked for CVEs                         │     │
│     │     // Updated regularly                        │     │
│     │ }                                               │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • OWASP Dependency-Check - Find vulnerable libs         │
│     • Snyk - Security scanning for dependencies             │
│     • npm audit / gradle dependencyCheck                    │
│     • GitHub Dependabot - Auto update alerts                │
│                                                             │
│  ✅ BEST PRACTICES:                                         │
│     • Only use well-known, maintained libraries             │
│     • Pin specific versions (not latest)                    │
│     • Regularly update dependencies                         │
│     • Verify checksums/signatures                           │
│     • Review library permissions                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M3: INSECURE AUTHENTICATION/AUTHORIZATION                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     Weak login system or improper permission checks         │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Weak password requirements (123456 allowed)           │
│     • No brute force protection                             │
│     • Client-side only authentication                       │
│     • Missing session timeout                               │
│     • Users can access other users' data                    │
│     • No multi-factor authentication for sensitive ops      │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. Attacker notices user ID in URL: /api/user/123       │
│     2. Changes to /api/user/124                             │
│     3. Server doesn't verify ownership                      │
│     4. Attacker sees another user's private data!           │
│     5. Can modify or delete other users' accounts           │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Try weak passwords (123456, password)                │
│     2. Attempt to access other user's resources             │
│     3. Modify user ID in requests                           │
│     4. Check if session expires properly                    │
│     5. Test login without proper credentials                │
│                                                             │
│  ⚠️ VULNERABLE CODE:                                        │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Client-side check only - WRONG!              │     │
│     │ if (user.role === "admin") {                    │     │
│     │     showAdminPanel();  // Can be bypassed!      │     │
│     │ }                                               │     │
│     │                                                 │     │
│     │ // No ownership verification - WRONG!           │     │
│     │ app.get('/api/user/:id', (req, res) => {        │     │
│     │     return db.getUser(req.params.id);           │     │
│     │ });                                             │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CODE:                                            │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Server-side verification - CORRECT!          │     │
│     │ app.get('/api/user/:id', (req, res) => {        │     │
│     │     if (req.user.id !== req.params.id) {        │     │
│     │         return res.status(403).send("Denied");  │     │
│     │     }                                           │     │
│     │     return db.getUser(req.params.id);           │     │
│     │ });                                             │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • Burp Suite - Intercept and modify requests            │
│     • OWASP ZAP - Automated auth testing                    │
│     • Frida - Bypass client-side checks                     │
│                                                             │
│  ✅ BEST PRACTICES:                                         │
│     • Always verify on server side                          │
│     • Implement proper session management                   │
│     • Use OAuth 2.0 / OpenID Connect                        │
│     • Add MFA for sensitive operations                      │
│     • Implement account lockout after failures              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M4: INSUFFICIENT INPUT/OUTPUT VALIDATION                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     Not checking/cleaning data that users enter             │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • SQL injection in database queries                     │
│     • XSS (Cross-Site Scripting) in WebViews                │
│     • Command injection                                     │
│     • Path traversal attacks                                │
│     • Buffer overflow from long inputs                      │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. Login form asks for username                         │
│     2. Attacker enters: admin'--                            │
│     3. Query becomes: SELECT * FROM users                   │
│        WHERE username='admin'--' AND password='x'           │
│     4. The -- comments out password check!                  │
│     5. Attacker logs in as admin without password!          │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Enter special characters: ' " < > ; --               │
│     2. Try SQL injection: ' OR '1'='1                       │
│     3. Test XSS: <script>alert('hack')</script>             │
│     4. Try path traversal: ../../etc/passwd                 │
│     5. Send very long strings to cause overflow             │
│                                                             │
│  ⚠️ VULNERABLE CODE:                                        │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // SQL Injection - DANGEROUS!                   │     │
│     │ String query = "SELECT * FROM users WHERE " +   │     │
│     │                "name = '" + userInput + "'";    │     │
│     │                                                 │     │
│     │ // XSS in WebView - DANGEROUS!                  │     │
│     │ webView.loadData(userInput, "text/html", null); │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CODE:                                            │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Parameterized query - SAFE!                  │     │
│     │ String query = "SELECT * FROM users WHERE " +   │     │
│     │                "name = ?";                      │     │
│     │ statement.setString(1, userInput);              │     │
│     │                                                 │     │
│     │ // Input validation - SAFE!                     │     │
│     │ if (!userInput.matches("[a-zA-Z0-9]+")) {       │     │
│     │     throw new InvalidInputException();          │     │
│     │ }                                               │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • SQLMap - Automated SQL injection testing              │
│     • Burp Suite - Input fuzzing                            │
│     • OWASP ZAP - XSS detection                             │
│                                                             │
│  ✅ VALIDATION CHECKLIST:                                   │
│     □ Validate input length                                 │
│     □ Check input type (number, string, email)              │
│     □ Use allowlist (only allowed characters)               │
│     □ Sanitize output before displaying                     │
│     □ Use parameterized queries for database                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M5: INSECURE COMMUNICATION                                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     Data sent over network is not properly protected        │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Using HTTP instead of HTTPS                           │
│     • Accepting all SSL certificates                        │
│     • No certificate pinning                                │
│     • Weak TLS versions (TLS 1.0, 1.1)                      │
│     • Ignoring SSL errors                                   │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. User connects to coffee shop WiFi                    │
│     2. Attacker is on same network                          │
│     3. App uses HTTP (no encryption)                        │
│     4. Attacker captures all traffic with Wireshark         │
│     5. Sees username, password, credit card in plain text!  │
│                                                             │
│     ┌─────────────────────────────────────────────────┐     │
│     │  [Your Phone]  ──HTTP──>  [Attacker]  ────>  [Server] │
│     │       |                      |                  │     │
│     │       |    "password123"     |                  │     │
│     │       |    ← Can see! →      |                  │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Use Wireshark to capture app traffic                 │
│     2. Check if data is readable (not encrypted)            │
│     3. Use Burp Suite as proxy                              │
│     4. Try to intercept with self-signed certificate        │
│     5. Check TLS version with SSL Labs                      │
│                                                             │
│  ⚠️ VULNERABLE CODE:                                        │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Using HTTP - DANGEROUS!                      │     │
│     │ String url = "http://api.example.com/login";    │     │
│     │                                                 │     │
│     │ // Trusting all certificates - DANGEROUS!       │     │
│     │ trustManager.checkServerTrusted(chain, type) {  │     │
│     │     // Empty - accepts anything!                │     │
│     │ }                                               │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CODE:                                            │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Always HTTPS - SAFE!                         │     │
│     │ String url = "https://api.example.com/login";   │     │
│     │                                                 │     │
│     │ // Certificate Pinning - SAFE!                  │     │
│     │ CertificatePinner pinner = new CertificatePinner│     │
│     │     .Builder()                                  │     │
│     │     .add("api.example.com", "sha256/AAAA...")   │     │
│     │     .build();                                   │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • Wireshark - Capture network traffic                   │
│     • Burp Suite - Man-in-the-middle testing                │
│     • SSL Labs - Check TLS configuration                    │
│     • tcpdump - Command line packet capture                 │
│                                                             │
│  📱 PLATFORM CONFIGURATION:                                 │
│     Android (network_security_config.xml):                  │
│     ┌─────────────────────────────────────────────────┐     │
│     │ <network-security-config>                       │     │
│     │   <domain-config cleartextTrafficPermitted=     │     │
│     │                  "false">                       │     │
│     │     <domain>api.example.com</domain>            │     │
│     │     <pin-set>                                   │     │
│     │       <pin digest="SHA-256">base64pin==</pin>   │     │
│     │     </pin-set>                                  │     │
│     │   </domain-config>                              │     │
│     │ </network-security-config>                      │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M6: INADEQUATE PRIVACY CONTROLS                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     App collects too much data or doesn't protect privacy   │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Collecting data you don't need                        │
│     • Logging sensitive information                         │
│     • Sharing data with third parties without consent       │
│     • No option to delete user data                         │
│     • Tracking users without permission                     │
│     • Storing PII (Personal Identifiable Information)       │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. App logs user activity for "debugging"               │
│     2. Logs include: email, location, browsing history      │
│     3. Log file gets exposed or hacked                      │
│     4. Thousands of users' private data leaked              │
│     5. Company faces GDPR fines + lawsuits!                 │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Check what permissions app requests                  │
│     2. Monitor network traffic for data being sent          │
│     3. Look for tracking SDKs (Facebook, Google, etc.)      │
│     4. Check if app works with minimal permissions          │
│     5. Review log files for sensitive data                  │
│                                                             │
│  ⚠️ VULNERABLE CODE:                                        │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Logging sensitive data - WRONG!              │     │
│     │ Log.d("Auth", "User: " + email);                │     │
│     │ Log.d("Auth", "Password: " + password);         │     │
│     │                                                 │     │
│     │ // Collecting unnecessary data - WRONG!         │     │
│     │ analytics.track("purchase", {                   │     │
│     │     "credit_card": cardNumber,                  │     │
│     │     "ssn": socialSecurity,                      │     │
│     │     "contacts": getAllContacts()                │     │
│     │ });                                             │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CODE:                                            │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // No sensitive data in logs - CORRECT!         │     │
│     │ Log.d("Auth", "Login attempted");               │     │
│     │                                                 │     │
│     │ // Collect only what you need - CORRECT!        │     │
│     │ analytics.track("purchase", {                   │     │
│     │     "amount": amount,                           │     │
│     │     "timestamp": time                           │     │
│     │ });                                             │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • Charles Proxy - Monitor outgoing data                 │
│     • Exodus Privacy - Detect tracking SDKs                 │
│     • MobSF - Check permissions and data handling           │
│                                                             │
│  ✅ PRIVACY CHECKLIST:                                      │
│     □ Only collect necessary data                           │
│     □ Get user consent before collection                    │
│     □ Provide data deletion option                          │
│     □ Never log sensitive information                       │
│     □ Anonymize data when possible                          │
│     □ Clear data on logout                                  │
│     □ Follow GDPR/CCPA requirements                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M7: INSUFFICIENT BINARY PROTECTIONS                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     App can be easily reverse-engineered or modified        │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • No code obfuscation                                   │
│     • No root/jailbreak detection                           │
│     • No tampering detection                                │
│     • Debug build released to public                        │
│     • No integrity checks                                   │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. Attacker downloads your app from store               │
│     2. Decompiles it with JADX (takes 5 minutes)            │
│     3. Reads all your code clearly                          │
│     4. Finds vulnerabilities and secrets                    │
│     5. Creates modified/cracked version of your app!        │
│                                                             │
│     ┌─────────────────────────────────────────────────┐     │
│     │  Without Obfuscation:                           │     │
│     │  public void validateLicense(String key) {      │     │
│     │      if (key.equals("SECRET-KEY-123")) {        │     │
│     │          unlockPremium();                       │     │
│     │      }                                          │     │
│     │  }                                              │     │
│     │  ↑ Attacker can read this easily!               │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│     ┌─────────────────────────────────────────────────┐     │
│     │  With Obfuscation:                              │     │
│     │  public void a(String b) {                      │     │
│     │      if (b.equals(c.d())) {                     │     │
│     │          e();                                   │     │
│     │      }                                          │     │
│     │  }                                              │     │
│     │  ↑ Much harder to understand!                   │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Decompile with JADX - is code readable?              │
│     2. Run on rooted device - does app detect it?           │
│     3. Modify APK and reinstall - does it still work?       │
│     4. Check if debugger can attach                         │
│     5. Look for integrity verification                      │
│                                                             │
│  ⚠️ VULNERABLE SETUP:                                       │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // build.gradle - No protection!                │     │
│     │ buildTypes {                                    │     │
│     │     release {                                   │     │
│     │         minifyEnabled false  // No obfuscation! │     │
│     │         debuggable true      // Debug enabled!  │     │
│     │     }                                           │     │
│     │ }                                               │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE SETUP:                                           │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // build.gradle - Protected!                    │     │
│     │ buildTypes {                                    │     │
│     │     release {                                   │     │
│     │         minifyEnabled true                      │     │
│     │         shrinkResources true                    │     │
│     │         debuggable false                        │     │
│     │         proguardFiles 'proguard-rules.pro'      │     │
│     │     }                                           │     │
│     │ }                                               │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • JADX - Decompile to check protection                  │
│     • Frida - Runtime manipulation testing                  │
│     • Objection - Mobile security testing                   │
│     • apktool - APK modification testing                    │
│                                                             │
│  ✅ PROTECTION METHODS:                                     │
│     □ Enable ProGuard/R8 obfuscation                        │
│     □ Add root/jailbreak detection                          │
│     □ Implement integrity checks                            │
│     □ Use anti-debugging techniques                         │
│     □ Consider commercial protection (DexGuard)             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M8: SECURITY MISCONFIGURATION                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     Insecure default settings or wrong security config      │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Debug mode enabled in production                      │
│     • Backup allowed (android:allowBackup="true")           │
│     • Components exported unnecessarily                     │
│     • Cleartext traffic allowed                             │
│     • Default credentials not changed                       │
│     • Unnecessary permissions requested                     │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. App has android:allowBackup="true"                   │
│     2. Attacker gets physical access to phone               │
│     3. Runs: adb backup com.yourapp                         │
│     4. Extracts backup file on computer                     │
│     5. Reads all app data including tokens and passwords!   │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Check AndroidManifest.xml settings                   │
│     2. Look for exported components                         │
│     3. Test if backup is enabled                            │
│     4. Check for debug mode                                 │
│     5. Review network security config                       │
│                                                             │
│  ⚠️ VULNERABLE CONFIGURATION:                               │
│     ┌─────────────────────────────────────────────────┐     │
│     │ <!-- AndroidManifest.xml - DANGEROUS! -->       │     │
│     │ <application                                    │     │
│     │     android:debuggable="true"                   │     │
│     │     android:allowBackup="true"                  │     │
│     │     android:usesCleartextTraffic="true">        │     │
│     │                                                 │     │
│     │     <activity                                   │     │
│     │         android:name=".SecretActivity"          │     │
│     │         android:exported="true" />              │     │
│     │                                                 │     │
│     │     <provider                                   │     │
│     │         android:name=".DataProvider"            │     │
│     │         android:exported="true" />              │     │
│     │ </application>                                  │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CONFIGURATION:                                   │
│     ┌─────────────────────────────────────────────────┐     │
│     │ <!-- AndroidManifest.xml - SECURE! -->          │     │
│     │ <application                                    │     │
│     │     android:debuggable="false"                  │     │
│     │     android:allowBackup="false"                 │     │
│     │     android:usesCleartextTraffic="false"        │     │
│     │     android:networkSecurityConfig=              │     │
│     │         "@xml/network_security_config">         │     │
│     │                                                 │     │
│     │     <activity                                   │     │
│     │         android:name=".SecretActivity"          │     │
│     │         android:exported="false" />             │     │
│     │                                                 │     │
│     │     <provider                                   │     │
│     │         android:name=".DataProvider"            │     │
│     │         android:exported="false"                │     │
│     │         android:permission="com.app.PRIVATE"/>  │     │
│     │ </application>                                  │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • MobSF - Automated manifest analysis                   │
│     • Drozer - Test exported components                     │
│     • adb - Test backup functionality                       │
│     • apktool - Extract and review config                   │
│                                                             │
│  ✅ SECURITY CHECKLIST:                                     │
│     □ debuggable = false                                    │
│     □ allowBackup = false (or use encrypted backup)         │
│     □ exported = false (unless needed)                      │
│     □ usesCleartextTraffic = false                          │
│     □ Minimum required permissions only                     │
│     □ No test credentials in production                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M9: INSECURE DATA STORAGE                                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     Sensitive data stored in unsafe locations               │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Passwords in SharedPreferences (plain text)           │
│     • Tokens in unencrypted SQLite database                 │
│     • Sensitive files on external storage (SD card)         │
│     • Credit card data in local files                       │
│     • Session data not cleared on logout                    │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. User's phone is rooted (or attacker gets access)     │
│     2. Attacker browses to /data/data/com.yourapp/          │
│     3. Opens shared_prefs/user_data.xml                     │
│     4. Finds: <string name="password">secret123</string>    │
│     5. Now has access to user's account!                    │
│                                                             │
│  📂 UNSAFE STORAGE LOCATIONS:                               │
│     ┌─────────────────────────────────────────────────┐     │
│     │  ❌ SharedPreferences (plain text XML)          │     │
│     │  ❌ SQLite databases (unencrypted)              │     │
│     │  ❌ External storage (/sdcard/)                 │     │
│     │  ❌ Cache directories                           │     │
│     │  ❌ Log files                                   │     │
│     │  ❌ Clipboard                                   │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Root device or use emulator                          │
│     2. Browse app's data directory                          │
│     3. Check SharedPreferences XML files                    │
│     4. Open SQLite databases                                │
│     5. Check external storage for app data                  │
│     6. Review cache and log directories                     │
│                                                             │
│  ⚠️ VULNERABLE CODE:                                        │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Storing in SharedPreferences - UNSAFE!       │     │
│     │ SharedPreferences prefs = getSharedPreferences( │     │
│     │     "user_data", MODE_PRIVATE);                 │     │
│     │ prefs.edit()                                    │     │
│     │     .putString("password", "secret123")         │     │
│     │     .putString("token", "abc-xyz-123")          │     │
│     │     .apply();                                   │     │
│     │                                                 │     │
│     │ // Stored as plain text in:                     │     │
│     │ // /data/data/com.app/shared_prefs/user_data.xml│     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CODE - ANDROID:                                  │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Using EncryptedSharedPreferences - SAFE!     │     │
│     │ MasterKey masterKey = new MasterKey.Builder(ctx)│     │
│     │     .setKeyScheme(MasterKey.KeyScheme.AES256_GCM│     │
│     │     .build();                                   │     │
│     │                                                 │     │
│     │ SharedPreferences securePrefs =                 │     │
│     │     EncryptedSharedPreferences.create(          │     │
│     │         context,                                │     │
│     │         "secure_prefs",                         │     │
│     │         masterKey,                              │     │
│     │         AES256_SIV,                             │     │
│     │         AES256_GCM                              │     │
│     │     );                                          │     │
│     │                                                 │     │
│     │ securePrefs.edit()                              │     │
│     │     .putString("token", "abc-xyz-123")          │     │
│     │     .apply();                                   │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CODE - iOS:                                      │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Using Keychain - SAFE!                       │     │
│     │ let query: [String: Any] = [                    │     │
│     │     kSecClass: kSecClassGenericPassword,        │     │
│     │     kSecAttrAccount: "userToken",               │     │
│     │     kSecValueData: tokenData,                   │     │
│     │     kSecAttrAccessible:                         │     │
│     │         kSecAttrAccessibleWhenUnlockedThisDevice│     │
│     │ ]                                               │     │
│     │ SecItemAdd(query as CFDictionary, nil)          │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • adb shell - Access Android file system                │
│     • SQLite Browser - Open database files                  │
│     • Frida - Runtime data extraction                       │
│     • objection - iOS data exploration                      │
│                                                             │
│  ✅ SAFE STORAGE OPTIONS:                                   │
│     ┌─────────────────────────────────────────────────┐     │
│     │  ✅ Android Keystore                            │     │
│     │  ✅ EncryptedSharedPreferences                  │     │
│     │  ✅ SQLCipher (encrypted database)              │     │
│     │  ✅ iOS Keychain                                │     │
│     │  ✅ Encrypted files with secure key             │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  M10: INSUFFICIENT CRYPTOGRAPHY                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ❌ WHAT'S WRONG:                                           │
│     Using weak, outdated, or incorrectly implemented        │
│     encryption                                              │
│                                                             │
│  📍 EXAMPLES:                                               │
│     • Using MD5 or SHA1 for passwords                       │
│     • Using DES or 3DES encryption                          │
│     • Hardcoded encryption keys                             │
│     • Using ECB mode (patterns visible)                     │
│     • Same IV (Initialization Vector) for all encryption    │
│     • Small key sizes (like 128-bit when 256 is needed)     │
│                                                             │
│  💀 REAL ATTACK SCENARIO:                                   │
│     1. App encrypts data with DES algorithm                 │
│     2. DES was cracked in 1999!                             │
│     3. Attacker captures encrypted data                     │
│     4. Uses modern computer to crack DES in hours           │
│     5. All "encrypted" data is now readable!                │
│                                                             │
│  📊 ALGORITHM STRENGTH COMPARISON:                          │
│     ┌─────────────────────────────────────────────────┐     │
│     │  Algorithm     │  Status      │  Crack Time    │     │
│     │  ─────────────────────────────────────────────  │     │
│     │  MD5           │  ❌ BROKEN   │  Seconds       │     │
│     │  SHA1          │  ❌ BROKEN   │  Minutes       │     │
│     │  DES           │  ❌ BROKEN   │  Hours         │     │
│     │  3DES          │  ⚠️ WEAK     │  Days          │     │
│     │  SHA256        │  ✅ SAFE     │  Centuries     │     │
│     │  AES-256       │  ✅ SAFE     │  Billions yrs  │     │
│     │  bcrypt/Argon2 │  ✅ SAFE     │  Very long     │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🔍 HOW TO TEST:                                            │
│     1. Decompile app and search for crypto usage            │
│     2. Look for: MD5, SHA1, DES, ECB, hardcoded keys        │
│     3. Check key sizes (should be 256-bit for AES)          │
│     4. Verify IV is random for each encryption              │
│     5. Check password hashing method                        │
│                                                             │
│  ⚠️ VULNERABLE CODE:                                        │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Weak hashing - BROKEN!                       │     │
│     │ MessageDigest md = MessageDigest.getInstance(   │     │
│     │     "MD5");  // Cracked!                        │     │
│     │                                                 │     │
│     │ // Weak encryption - BROKEN!                    │     │
│     │ Cipher cipher = Cipher.getInstance(             │     │
│     │     "DES/ECB/PKCS5Padding");  // Double bad!    │     │
│     │                                                 │     │
│     │ // Hardcoded key - DANGEROUS!                   │     │
│     │ byte[] key = "MySecretKey12345".getBytes();     │     │
│     │                                                 │     │
│     │ // Same IV every time - DANGEROUS!              │     │
│     │ byte[] iv = "1234567890123456".getBytes();      │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  ✅ SECURE CODE:                                            │
│     ┌─────────────────────────────────────────────────┐     │
│     │ // Strong encryption - SAFE!                    │     │
│     │ Cipher cipher = Cipher.getInstance(             │     │
│     │     "AES/GCM/NoPadding");  // AES-GCM is best!  │     │
│     │                                                 │     │
│     │ // Generate random key - SAFE!                  │     │
│     │ KeyGenerator keyGen = KeyGenerator.getInstance( │     │
│     │     "AES");                                     │     │
│     │ keyGen.init(256);  // 256-bit key               │     │
│     │ SecretKey key = keyGen.generateKey();           │     │
│     │                                                 │     │
│     │ // Random IV every time - SAFE!                 │     │
│     │ byte[] iv = new byte[12];                       │     │
│     │ new SecureRandom().nextBytes(iv);               │     │
│     │                                                 │     │
│     │ // For passwords use bcrypt/Argon2 - SAFE!      │     │
│     │ String hash = BCrypt.hashpw(password,           │     │
│     │     BCrypt.gensalt(12));                        │     │
│     └─────────────────────────────────────────────────┘     │
│                                                             │
│  🛠️ TOOLS TO USE:                                           │
│     • MobSF - Detect weak crypto                            │
│     • Cryptosense - Crypto analysis                         │
│     • Manual code review                                    │
│                                                             │
│  ✅ CRYPTO CHECKLIST:                                       │
│     □ Use AES-256 for encryption (GCM mode)                 │
│     □ Use SHA-256 or SHA-3 for hashing                      │
│     □ Use bcrypt/Argon2/PBKDF2 for passwords                │
│     □ Generate random keys (never hardcode)                 │
│     □ Use random IV for each encryption                     │
│     □ Store keys in Keystore/Keychain                       │
│     □ Never use: MD5, SHA1, DES, ECB mode                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```