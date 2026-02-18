#  OWASP Top 10:2025
---

## A01:2025 — Broken Access Control 
**Meaning:** Users can access data/actions they should not.  
 "Authorization is not enforced properly on server-side."

### Common Examples
- [x] IDOR (change `id=1001 → 1002`)
- [x] Missing function-level access control
- [x] Forced browsing to admin endpoints
- [x] Privilege escalation (User → Admin)

---

## A02:2025 — Security Misconfiguration 
**Meaning:** Wrong/default configurations expose the system.  
Secure settings are missing or misconfigured."

### Common Examples
- [x] Debug mode enabled / verbose errors
- [x] Directory listing enabled
- [x] Default credentials
- [x] Missing security headers
- [x] Exposed admin panels


---

## A03:2025 — Software Supply Chain Failures 
**Meaning:** Risk from third-party libraries, build pipeline, dependencies.  
"Application depends on components that may be compromised."

### Common Examples
- [x] Dependency poisoning
- [x] Compromised NPM/PyPI packages
- [x] CI/CD secrets leaked
- [x] Untrusted third-party scripts
---

## A04:2025 — Cryptographic Failures 
**Meaning:** Sensitive data is not properly protected.  
"Weak crypto, missing TLS, or insecure storage of secrets."

### Common Examples
- [x] HTTP instead of HTTPS
- [x] Weak password hashing (MD5/SHA1)
- [x] Sensitive data in URL/logs
- [x] No encryption for PII/secrets
---

## A05:2025 — Injection 
**Meaning:** Attacker input is executed by backend.  
"Untrusted input is interpreted as code/query."

### Common Examples
- [x] SQL Injection
- [x] Command Injection
- [x] NoSQL Injection
- [x] LDAP Injection
---

## A06:2025 — Insecure Design 
**Meaning:** Security was not considered in the app design.  
"The design allows abuse even if code has no bugs."

### Common Examples
- [x] No rate limiting (bruteforce possible)
- [x] Weak password reset flow
- [x] OTP reuse / unlimited attempts
- [x] Business logic flaws



---

## A07:2025 — Authentication Failures
**Meaning:** Login/session handling is weak.  
"Weak authentication allows account takeover."

### Common Examples
- [x] Weak password policy
- [x] No MFA (where required)
- [x] Session not invalidated after logout
- [x] Session fixation
---

## A08:2025 — Software or Data Integrity Failures
**Meaning:** App trusts data/code without integrity checks.  
 "Updates/data are accepted without validation."

### Common Examples
- [ ] Unsigned updates
- [ ] Insecure deserialization
- [ ] CDN scripts without integrity checking
- [ ] Tampering of important client-side data
---

## A09:2025 — Security Logging and Alerting Failures 
**Meaning:** Attacks happen but no logs/alerts exist.  
"Without logging, detection and incident response fails."

### Common Examples
- [ ] No logs for login failures
- [ ] No alerts on brute force
- [ ] No monitoring for privilege changes
---

## A10:2025 — Mishandling of Exceptional Conditions
**Meaning:** Errors/exceptions leak info or break security.  
"Improper exception handling exposes internals or bypasses controls."

### Common Examples
- [ ] Stack traces showing file paths/code
- [ ] SQL errors revealing queries
- [ ] App crashes on invalid input
- [ ] 500 errors leaking sensitive details
---
## Must Know Well
- A01 Broken Access Control  
- A04 Cryptographic Failures  
- A05 Injection  
- A07 Authentication Failures  
- A02 Security Misconfiguration  

## Good to Know (Very Useful)
- A06 Insecure Design  
- A03 Supply Chain Failures  
- A08 Integrity Failures  
- A10 Exceptional Conditions  

## Mostly Theory (But Mentionable)
- A09 Logging and Alerting Failures  

---
