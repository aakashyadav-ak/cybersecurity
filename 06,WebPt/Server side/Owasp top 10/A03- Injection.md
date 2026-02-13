**Injection** happens when untrusted user input is sent into an interpreter without proper validation/sanitization.

**“Injection occurs when user input is treated as code/command instead of data.”**

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
| 9   | Header Injection                  | HTTP headers, redirects                 | Response splitting, cache poisoning     |
| 10  | CRLF Injection                    | URLs/headers                            | Cookie injection, redirect manipulation |


# [[09. SQL Injection]]

# [[03.XSS (Cross site scripting)]]

# [[]]