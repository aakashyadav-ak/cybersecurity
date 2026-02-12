## A02:2025 - Cryptographic Failures (VAPT Fresher Interview)

| # | Vulnerability Type | Possible Outcomes |
|---|---------------------|------------------|
| 1 | Sensitive Data Sent Over HTTP (No TLS) | Credential/session theft, MITM attacks |
| 2 | Weak / Deprecated TLS Configuration (TLS 1.0/1.1, weak ciphers) | Traffic decryption, downgrade attacks |
| 3 | Missing HSTS | SSL stripping, forced HTTP downgrade |
| 4 | Weak Password Hashing (MD5/SHA1/no salt) | Fast password cracking, account takeover |
| 5 | Hardcoded Secrets (API keys, DB creds) | Full system compromise, data breach |
| 6 | Sensitive Data Exposure in Responses/Logs | PII leakage, compliance issues |
| 7 | Weak / Predictable Tokens (Reset links, session IDs) | Account takeover, session hijacking |
| 8 | Insecure JWT Implementation (none alg, weak secret) | Auth bypass, privilege escalation |
| 9 | Encryption Missing for Sensitive Data at Rest | Database compromise leads to readable PII |

## A02:2025 - Cryptographic Failures (Types)

| # | Type (What is wrong) | Simple Example |
|---|-----------------------|----------------|
| 1 | No Encryption in Transit | Login page on HTTP instead of HTTPS |
| 2 | Weak / Deprecated TLS | TLS 1.0, weak cipher suites |
| 3 | Missing HTTPS Enforcement | No HSTS, allows SSL stripping |
| 4 | Weak Password Storage | MD5/SHA1 hashes, no salt |
| 5 | Weak / Broken Crypto Algorithms | DES/RC4, small key sizes |
| 6 | Poor Key Management | Hardcoded keys, exposed private keys |
| 7 | Sensitive Data Exposure | PII in URL, logs, error messages |
| 8 | Weak Tokens / Randomness | Predictable reset tokens/session IDs |
| 9 | Misuse of JWT / Crypto Libraries | `alg=none`, weak JWT secret |
# **Cryptographic Failures** happens when an application:
- does **not protect sensitive data properly**
- uses **weak encryption**
- uses **wrong crypto implementation**
- exposes secrets (keys/passwords/tokens)


> **“ Cryptographic Failures is when encryption is missing, weak, or misused, causing data exposure.”**

> "**Failures related to cryptography that lead to exposure of sensitive data.**"

# What data is considered sensitive?
- Passwords
- Session cookies / JWT tokens
- Reset tokens / OTP
- API keys
- Credit card details
- Aadhaar/PAN/PII
- Bank account details
- Medical data
- Internal system secrets

---

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   Sensitive Data exists in THREE states:                     │
│                                                              │
│   1. DATA IN TRANSIT     → Moving over network              │
│      (HTTP, API calls)     Must be encrypted (HTTPS/TLS)    │
│                                                              │
│   2. DATA AT REST        → Stored in database/disk          │
│      (DB, files, backups)  Must be encrypted (AES/hashing)  │
│                                                              │
│   3. DATA IN USE         → Being processed in memory        │
│      (RAM, application)    Minimize exposure window         │
│                                                              │
│   Cryptographic Failure = Any of these states are            │
│   UNPROTECTED or WEAKLY PROTECTED                           │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```
# Types 

## 1) HTTP Instead of HTTPS (No Encryption in Transit)
### What is it?
Sensitive data travels in plain text.
```
┌──────────┐         PLAINTEXT         ┌──────────┐
│  User's  │ ════════════════════════▶ │  Web     │
│  Browser │    HTTP (Port 80)         │  Server  │
│          │    NO encryption          │          │
│          │    Anyone can READ        │          │
└──────────┘                           └──────────┘
      │
      │  Attacker on same network
      │  (WiFi, ISP, corporate LAN)
      │
      ▼
┌──────────┐
│ ATTACKER │ ← Captures EVERYTHING:
│ (Sniffer)│   → Usernames & Passwords
│          │   → Session cookies
│          │   → Credit card numbers
│          │   → Personal messages
│          │   → API keys
└──────────┘

This attack is called: MAN-IN-THE-MIDDLE (MitM)
```
### Example
- `http://site.com/login`
- API requests over HTTP
```
───────────────────────────────────────────────────
Example 1: Login over HTTP
───────────────────────────────────────────────────

  User submits login form:
  
  POST http://bank.com/login        ◄── HTTP not HTTPS!
  Content-Type: application/x-www-form-urlencoded
  
  username=ravi&password=MySecret@123

  Attacker on same WiFi runs Wireshark:
  → Captures: username=ravi, password=MySecret@123
  → Attacker logs in as Ravi!

───────────────────────────────────────────────────
Example 2: Session Cookie over HTTP
───────────────────────────────────────────────────

  Even if login page is HTTPS, but rest of site is HTTP:
  
  https://shop.com/login         → Secure login ✓
  http://shop.com/dashboard      → Cookie sent over HTTP! ✗
  
  Set-Cookie: session=abc123xyz   ◄── No "Secure" flag!
  
  Attacker captures session cookie → Session Hijacking!

───────────────────────────────────────────────────
Example 3: API calls over HTTP
───────────────────────────────────────────────────

  Mobile app makes API call:
  GET http://api.company.com/users/me
  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
  
  Attacker captures JWT token
  → Uses it to impersonate the user!
```

### Testing
```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Manual Testing:                                             │
│  □ Type http:// instead of https:// → Does site load?      │
│  □ Does http:// redirect to https:// ? (301 redirect)      │
│  □ Check login form action URL → http or https?            │
│  □ Check if mixed content exists (HTTPS page loading        │
│    HTTP resources like images, scripts, CSS)                │
│  □ Check Set-Cookie header → "Secure" flag present?        │
│  □ Check API endpoints → HTTP accessible?                  │
│                                                              │
│  Tools:                                                      │
│  □ Burp Suite → Check protocol in requests                 │
│  □ Browser DevTools → Console shows mixed content warnings │
│  □ curl -I http://target.com → Check response headers      │
│  □ sslyze → TLS configuration analysis                     │
│  □ testssl.sh → Comprehensive TLS testing                  │
│  □ Wireshark → Capture and verify plaintext traffic        │
│                                                              │
│  Check for HSTS header:                                      │
│  Strict-Transport-Security: max-age=31536000;              │
│  includeSubDomains; preload                                 │
│  → If MISSING = vulnerable to SSL stripping attacks        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```
### Impact
- MITM attack
- credential theft
- session hijacking

### Mitigation
1. ENFORCE HTTPS everywhere (entire site, not just login)
2. Redirect HTTP → HTTPS (301 permanent redirect)
3. Implement HSTS header
   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
4. Set "Secure" flag on ALL cookies
   Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict
5. No mixed content (all resources loaded via HTTPS)
6. Use HSTS Preload list (browser enforces HTTPS before first visit)
7. Disable HTTP entirely on production (close port 80)
   Or redirect all port 80 traffic to port 443
---

## 2) Weak TLS / Old Versions
### What is it?
Server supports insecure TLS versions or weak cipher suites.
 ==TLS 1.3(version)    Most secure, fastest== (latest version of TLS)
### Common examples
- TLS 1.0 / TLS 1.1 enabled
- Weak ciphers like RC4 / 3DES
- Bad certificate config

### Cypher Suite
```
A cipher suite defines HOW encryption works in TLS:

TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
│    │      │        │    │    │
│    │      │        │    │    └── Hash function (integrity)
│    │      │        │    └─────── Mode (GCM = authenticated)
│    │      │        └──────────── Encryption algorithm + key size
│    │      └───────────────────── Authentication method
│    └──────────────────────────── Key exchange method
└───────────────────────────────── Protocol


WEAK Cipher Suites (should be DISABLED):
──────────────────────────────────────────
  → RC4           (broken stream cipher)
  → DES / 3DES   (small key size, Sweet32 attack)
  → MD5           (broken hash)
  → CBC mode      (vulnerable to BEAST, Lucky13)
  → NULL ciphers  (NO encryption at all!)
  → EXPORT ciphers (intentionally weakened, FREAK attack)
  → Anonymous DH   (no authentication, MitM possible)

STRONG Cipher Suites (should be ENABLED):
──────────────────────────────────────────
  → AES-256-GCM
  → AES-128-GCM
  → CHACHA20-POLY1305
  → ECDHE key exchange (forward secrecy)
```

### Testing
```
Tool 1: testssl.sh (BEST for interviews)
─────────────────────────────────────────
  ./testssl.sh https://target.com
  
  Output shows:
  → Supported TLS versions
  → Cipher suites (strong/weak)
  → Known vulnerabilities (POODLE, BEAST, etc.)
  → Certificate details
  → Forward secrecy support
  → HSTS header presence

Tool 2: sslyze
─────────────────
  sslyze --regular target.com
  
Tool 3: Nmap
─────────────
  nmap --script ssl-enum-ciphers -p 443 target.com
  → Lists all supported cipher suites with grades

Tool 4: SSL Labs (Online)
──────────────────────────
  https://www.ssllabs.com/ssltest/
  → Gives A+ to F grade
  → Very detailed report
  → Commonly referenced in VAPT reports

Tool 5: Burp Suite
──────────────────
  → Proxy → Options → TLS settings
  → Check for weak protocol support
```
### Impact
- traffic decryption
- downgrade attacks

### Fix
1. Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
2. Enable ONLY TLS 1.2 and TLS 1.3
3. Disable weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
4. Enable forward secrecy (ECDHE key exchange)
5. Use strong ciphers: AES-256-GCM, CHACHA20-POLY1305
6. Keep OpenSSL/libraries updated (patch Heartbleed etc.)
7. Use 2048-bit or higher RSA keys (4096-bit recommended)
8. Enable HSTS to prevent protocol downgrade attacks
9. Disable TLS compression (prevents CRIME attack)
10. Regular scanning with testssl.sh / SSL Labs

---

## 3) Weak Password Hashing / Storage
### What is it?
Passwords stored using weak hashing algorithms.

### Bad examples
- MD5
- SHA1
- SHA256 without salt
- plain text password storage (worst)

### Impact
- offline cracking
- credential stuffing
- full account compromise

### Fix
Use strong hashing:
- bcrypt
- scrypt
- Argon2

---

## 4) Hardcoded Secrets / Exposed Keys
### What is it?
Secrets are stored in code or leaked in public places.

### Examples
- API keys in JavaScript source
- DB password inside config file
- `.env` file exposed
- AWS keys pushed to GitHub

### Impact
- full system compromise
- database breach
- unauthorized API access

### Fix
- store secrets in secret manager / vault
- rotate keys
- remove secrets from client-side code

---

## 5) Sensitive Data Exposure (Responses / Logs / URLs)
### What is it?
Sensitive data is revealed in:
- API responses
- error messages
- logs
- URL parameters

### Examples
- `/reset?token=abcd1234`
- API returns full Aadhaar/PAN
- debug mode leaks secrets

### Impact
- PII leakage
- compliance violations
- account takeover

### Fix
- mask sensitive fields
- do not log secrets
- never put tokens in URLs

---

## 6) Weak Reset Tokens / Predictable Randomness
### What is it?
Reset tokens/session IDs are guessable.

### Examples
- reset token = incremental number
- short OTP with unlimited attempts
- session ID predictable

### Impact
- account takeover
- session hijacking

### Fix
- use cryptographically secure random tokens
- rate limit attempts
- expire tokens quickly

---

# 🟡 Optional (Good to know, not mandatory for fresher)

## 7) Missing HSTS
### What is it?
Browser can be forced to use HTTP.

### Fix
Enable:
- `Strict-Transport-Security` header

---

## 8) JWT Crypto Mistakes
### Examples
- weak secret key
- `alg=none`
- no token expiry

### Impact
- authentication bypass
- privilege escalation

---

## 9) No Encryption at Rest
### What is it?
Sensitive data stored unencrypted in DB.

### Impact
If DB leaks → data is readable.

---

# 🧪 How to Test A02 Quickly (VAPT)

## TLS Testing
- Check if HTTPS exists
- Check TLS versions supported
- Look for weak ciphers

## Sensitive Data Checks
- Inspect responses for PII
- Check if tokens appear in URL
- Check logs/debug pages

## Password Storage (if you get DB access)
- Identify hashing algorithm
- Check if salts exist

---

# ✅ Common Tools Used
- Browser DevTools (Network tab)
- Burp Suite
- SSLScan / testssl.sh
- Nmap NSE (ssl-enum-ciphers)

---

# 🧠 Interview Q&A (Quick)

### Q1: What is A02?
**A02 is cryptographic failures: when sensitive data is not encrypted properly or crypto is weak/misused.**

### Q2: Give examples
- HTTP login page
- weak TLS 1.0 enabled
- MD5 password hashes
- API keys exposed in source code

### Q3: What is the best fix for password hashing?
**Use bcrypt / Argon2 with salt.**

---

# 📌 One-line Summary
> **A02 = Weak encryption + exposed secrets + weak password storage → data theft & account takeover**
