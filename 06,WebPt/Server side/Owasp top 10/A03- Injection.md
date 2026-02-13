- **Injection** happens when untrusted user input is sent into an interpreter without proper validation/sanitization.

- **“==Injection occurs when user input is treated as code/command instead of data.==”**

- Injection occurs when an attacker sends untrusted/malicious data to an interpreter as part of a command or query. The application fails to validate, filter, or sanitize user input, causing the interpreter to execute unintended commands or access unauthorized data.

- You type something malicious in an input field (login, search, URL), and the server treats it as a command instead of normal text.

**This allows an attacker to execute:**
- database queries
- OS commands
- LDAP queries
- NoSQL queries
- template expressions

**Injection can lead to:**
- authentication bypass
- data leakage
- data modification/deletion
- Remote Code Execution (RCE)
- full server compromise

## Types of Injection (VAPT Fresher)

| #   | Injection Type                    | Where It Happens                        | Common Outcome                          |
| --- | --------------------------------- | --------------------------------------- | --------------------------------------- |
| 1   | ✅SQL Injection (SQLi)             | Login forms, search, APIs               | DB dump, auth bypass                    |
| 2   | ✅Command Injection (OS Injection) | Ping/tools, file convert, backend calls | RCE, server takeover                    |
| 3   | ✅Cross-Site Scripting (XSS)       | Web pages, input fields                 | Session theft, phishing                 |
| 4   | LDAP Injection                    | AD/LDAP login, directory search         | Auth bypass, user enum                  |
| 5   | ✅NoSQL Injection                  | MongoDB-based APIs                      | Auth bypass, data leak                  |
| 6   | XPath Injection                   | XML-based apps                          | Data extraction, auth bypass            |
| 7   | ✅XXE (XML External Entity)        | XML parsers                             | File read, SSRF                         |
| 8   | SSTI (Template Injection)         | Jinja2, Twig, Freemarker                | RCE                                     |
| 9   | Host Header Injection             | HTTP headers, redirects                 | Response splitting, cache poisoning     |
| 10  | CRLF Injection                    | URLs/headers                            | Cookie injection, redirect manipulation |


# [[09. SQL Injection]]

# [[20.OS Command Injection]]

# [[03.XSS (Cross site scripting)]]
