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
