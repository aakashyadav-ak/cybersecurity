# ✅ OWASP Top 10 (Interview Notes for VAPT Fresher)

## A01: Broken Access Control
**Meaning:** Users can access things they should not.
**Interview line:** "Access control is not properly enforced on server-side."

### Common Examples
- [x] IDOR (Insecure Direct Object Reference)
- [x] Accessing other users’ data by changing `id=1001 → 1002`
- [x] Missing authorization on APIs
- [x] Admin pages accessible to normal users

### How to Test (Basic)
- [x] Change user IDs / object IDs
- [x] Test role-based access (user vs admin)
- [x] Directly call API endpoints without permission

---

## A02: Cryptographic Failures
**Meaning:** Sensitive data is not properly protected.
**Interview line:** "Weak encryption, missing HTTPS, or improper storage of secrets."

### Common Examples
- [x] HTTP instead of HTTPS
- [x] Weak hashing like MD5/SHA1 for passwords
- [x] Sensitive data in URL
- [x] No encryption for PII

### How to Test
- [ ] Check TLS/SSL config
- [x] Look for sensitive data in responses
- [x] Check password storage method (if possible)

---

## A03: Injection
**Meaning:** Attacker sends input that gets executed by backend.
**Interview line:** "Untrusted input is interpreted as command/query."

### Common Examples
- [x] SQL Injection
- [x] Command Injection
- [ ] LDAP Injection
- [ ] NoSQL Injection

### How to Test
- [x] `' OR 1=1--`
- [x] `; whoami`
- [x] Use Burp + payloads
- [x] Look for errors or abnormal responses

---

## A04: Insecure Design
**Meaning:** Application design itself is weak.
**Interview line:** "Security was not considered in design stage."

### Common Examples
- [ ] No rate limiting (bruteforce possible)
- [ ] No account lockout
- [ ] Weak password reset design
- [ ] Business logic flaws

### How to Test
- [ ] Try abuse scenarios (logic testing)
- [ ] Check password reset flow
- [ ] Check OTP reuse / unlimited attempts

---

## A05: Security Misconfiguration
**Meaning:** Wrong configurations expose the app.
**Interview line:** "Default settings or misconfigured services cause exposure."

### Common Examples
- [ ] Directory listing enabled
- [ ] Debug mode enabled
- [ ] Default credentials
- [ ] Exposed admin panels
- [ ] Verbose error messages

### How to Test
- [ ] Check headers, errors, exposed endpoints
- [ ] Look for default login pages
- [ ] Scan with Nmap/Nikto

---

## A06: Vulnerable and Outdated Components
**Meaning:** Old libraries/frameworks have known vulnerabilities.
**Interview line:** "Using outdated dependencies leads to known CVEs."

### Common Examples
- [ ] Old WordPress plugins
- [ ] Vulnerable jQuery / Log4j / Struts
- [ ] Unpatched CMS

### How to Test
- [ ] Identify versions from headers/source
- [ ] Use CVE search / scanners
- [ ] Use Nuclei templates

---

## A07: Identification and Authentication Failures
**Meaning:** Login/auth is weak.
**Interview line:** "Weak authentication allows account takeover."

### Common Examples
- [ ] Weak password policy
- [ ] No MFA
- [ ] Session fixation
- [ ] Credential stuffing possible

### How to Test
- [ ] Try brute force (only in scope)
- [ ] Check session cookie behavior
- [ ] Test logout invalidation

---

## A08: Software and Data Integrity Failures
**Meaning:** App trusts untrusted updates/code.
**Interview line:** "Integrity of code/data is not verified."

### Common Examples
- [ ] Insecure CI/CD pipeline
- [ ] Dependency poisoning
- [ ] Unsigned updates
- [ ] Deserialization issues (sometimes linked)

### How to Test (Fresher level)
- [ ] Look for insecure update mechanisms
- [ ] Check if app loads scripts from untrusted sources

---

## A09: Security Logging and Monitoring Failures
**Meaning:** Attacks are not detected or logged.
**Interview line:** "Lack of logging makes incident response difficult."

### Common Examples
- [ ] No logs for login failures
- [ ] No alerting on brute force
- [ ] No monitoring for privilege changes

### How to Test
- [ ] Attempt failed logins and ask if logs exist (in VAPT report)
- [ ] Check if suspicious actions are tracked

---

## A10: Server-Side Request Forgery (SSRF)
**Meaning:** Attacker forces server to make internal requests.
**Interview line:** "Server fetches URLs based on user input."

### Common Examples
- [ ] URL fetch feature (image fetch, PDF fetch)
- [ ] Cloud metadata access (`169.254.169.254`)
- [ ] Internal port scanning

### How to Test
- [ ] Try internal URLs (localhost, 127.0.0.1)
- [ ] Try metadata IP
- [ ] Observe response timing / errors
