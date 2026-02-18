## Permission Failure / Authorization Failure
Broken access control is ==a security vulnerability where users can access data or perform actions beyond their authorized permissions==. This occurs when an application fails to enforce rules that restrict what an authenticated user can do, allowing attackers to view sensitive data, modify records, or escalate their privileges.

**Broken Access Control is a failure of AUTHORIZATION, not authentication. The user is already properly logged in and identified. The vulnerability exists because the server fails to verify whether that authenticated user has the PERMISSION to perform the requested action or access the requested resource.**

Common examples include forcing a URL to change from `/user/profile/101` to `/user/profile/102` to view another user's profile

```
┌─────────────────────────────────────────────────────────────┐
│                    ACCESS CONTROL                           │
├─────────────────────────────────────────────────────────────┤
│  Authentication  →  "Who are you?"                          │
│  Authorization   →  "What can you do?"                      │
│  Access Control  →  "Enforcing these rules"                 │
└─────────────────────────────────────────────────────────────┘
```

## Outcomes 
#### A. Vertical Privilege Escalation

This is when a lower-privileged user (like a standard customer) gains access to functions reserved for higher-privileged users (like an Administrator).

- **Example:** A standard user accesses `https://website.com/admin` because the server doesn't check if the user is actually an admin.

#### B. Horizontal Privilege Escalation

This is when a user gains access to resources belonging to another user of the same level.

- **Example:** User A (ID: 101) changes a URL parameter to ID: 102 and views User B's private messages.

## Types of Broken Access Control

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      A01:2025 - BROKEN ACCESS CONTROL                    │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│       TYPES                                          OUTCOMES            │
│   (What is broken)                                   (What happens)      │
│                                                                          │
│   ┌──────────────────────────────────────────────┐   ┌──────────────────┐│
│   │                                              │   │                  ││
│   │ 1) IDOR / BOLA                               │   │ • Horizontal     ││
│   │    (Accessing other user's object/data)      │   │   Privilege Esc. ││
│   │                                              │   │   User A → User B││
│   │ 2) Missing Function-Level Access Control     │   │                  ││
│   │    (User can access admin endpoints)         │──▶│ • Vertical       ││
│   │                                              │   │   Privilege Esc. ││
│   │ 3) Forced Browsing                           │   │   User → Admin   ││
│   │    (Guessing hidden URLs/APIs)               │   │                  ││
│   │                                              │   │ • Unauthorized   ││
│   │ 4) Missing Authorization Checks on APIs      │   │   Actions        ││
│   │    (Server does not validate role/ownership) │   │   delete/update  ││
│   │                                              │   │                  ││
│   │ 5)  JWT/Token Manipulation                   │   │ • Unauthorized   ││
│   │                                              │   │   Data Access    ││
│   │                                              │   │                  ││
│   └──────────────────────────────────────────────┘   └──────────────────┘│
│                                                                          │
│    "Broken Access Control = Missing Authorization"                       │
│   (NOT authentication, NOT input validation)                             │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

```

| #   | Vulnerability Type        | Possible Outcomes              |
| --- | ------------------------- | ------------------------------ |
| 1   | IDOR                      | Horizontal/Vertical Escalation |
| 2   | Forced Browsing           | Vertical Escalation            |
| 3   | Missing Function-Level AC | Vertical Escalation            |



```
┌─────────────────────────────────────────────────────────────────────────┐
│                    TECHNIQUES → EXPLOIT → VULNERABILITY                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   TECHNIQUE                        EXPLOITS                             │
│                                                                         │
│   Parameter Manipulation    ────▶  IDOR                                 │
│   (/user?id=123 → id=456)          (Access other user's data)           │
│                                                                         │
│   Cookie Manipulation       ────▶  IDOR / Missing Function-Level AC     │
│   (user_id=5 → user_id=6)          (Session-based access bypass)        │
│                                                                         │
│   JWT/Token Manipulation    ────▶  IDOR / Missing Function-Level AC     │
│   (role:user → role:admin)         (Token-based access bypass)          │
│                                                                         │
│   HTTP Method Tampering     ────▶  Missing Function-Level AC            │
│   (GET blocked, try POST)          (Method-based restrictions bypass)   │
│                                                                         │
│   Header/Metadata Manip.    ────▶  Forced Browsing / Function-Level AC  │
│   (X-Original-URL: /admin)         (Header-based access bypass)         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

| Vulnerability Type     | What's Manipulated | Unauthorized Access To |
| ---------------------- | ------------------ | ---------------------- |
| IDOR                   | Object IDs         | Other users' data      |
| Forced Browsing        | URL paths          | Hidden pages/APIs      |
| Parameter Manipulation | Request params     | Restricted functions   |
| Cookie Manipulation    | Cookie values      | Other sessions/roles   |

# [[03- IDOR]]

# 02- Missing Function-Level Access Control
The application has ADMIN functions (endpoints/pages)
But does NOT verify if the requesting user is actually an ADMIN

UI may hide the button → But the endpoint is still ACCESSIBLE
"Security through obscurity is NOT security"

### Example:
```
Scenario: HR Management System

Normal Employee Dashboard:
  GET /dashboard         → Shows employee's own data ✓
  GET /my-leaves         → Shows leave history ✓

Admin Panel (hidden from UI for normal users):
  GET /admin/all-employees       → Lists ALL employees
  POST /admin/salary/update      → Changes salary
  DELETE /admin/employee/1001    → Fires an employee!

Attack:
  Employee simply types /admin/all-employees in browser
  Server response: 200 OK + All employee data!

WHY?
  → The "Admin" link was hidden from the UI (front-end)
  → But the SERVER never checked the user's ROLE
```

### Testing Approach
**Step 1:** Login as ADMIN → Map ALL endpoints using Burp Spider/Crawl
**Step 2:** Make a list of admin-only endpoints:
        /admin/users
        /admin/settings
        /admin/reports
        /api/admin/create-user
        /api/admin/delete-user

**Step 3:** Login as NORMAL USER → Try accessing each admin endpoint
**Step 4:** Check responses:
        → 403 Forbidden = PROPERLY PROTECTED ✓
        → 200 OK with data = VULNERABLE ✗
        → 302 Redirect to login = Check if data leaks in response body

### Common Places to Find Hidden Endpoints
```
┌──────────────────────────────────────────────────┐
│  Source                 │  What to look for       │
├─────────────────────────┼────────────────────────┤
│  JavaScript files       │  API routes, endpoints  │
│  robots.txt             │  Disallowed paths       │
│  sitemap.xml            │  All mapped URLs        │
│  HTML comments          │  <!-- admin panel -->   │
│  Swagger/OpenAPI docs   │  /swagger-ui, /api-docs │
│  Mobile app source      │  Hardcoded API URLs     │
│  Wayback Machine        │  Historical endpoints   │
│  Directory brute-force  │  /admin, /manager, etc  │
└──────────────────────────────────────────────────┘
```
# [[15.Forced Browsing (server side)]]

## Missing Authorization 
### Missing Authorization Checks on APIs  (Server does not validate role/ownership)
```
This is the WORST case:
  → Not just wrong role accessing it
  → COMPLETELY UNAUTHENTICATED user can access the API
  → NO token/session required AT ALL

┌────────────────┐         ┌──────────────┐         ┌──────────────┐
│  Anonymous     │ ──GET──▶│   API Server │ ──SQL──▶│   Database   │
│  Attacker      │ /api/   │              │         │              │
│  (NO login)    │ users/  │  Checks:     │ SELECT  │ Returns ALL  │
│  (NO token)    │ all     │  ❌ Logged in?│ * FROM  │ user data!   │
│                │         │  ❌ Has role? │ users   │              │
│                │ ◄───────│  NO CHECK    │         │              │
│  Gets ALL      │  200 OK │  AT ALL!     │         │              │
│  user data!    │         │              │         │              │
└────────────────┘         └──────────────┘         └──────────────┘
```

#### example:
```
# No authentication token, no session, NOTHING

curl https://api.company.com/api/v1/users

Response (200 OK):
{
  "users": [
    {"id": 1, "name": "Admin", "email": "admin@company.com", 
     "password_hash": "$2b$12$..."},
    {"id": 2, "name": "Ravi", "email": "ravi@company.com",
     "password_hash": "$2b$12$..."},
    ...
    5000 more users
  ]
}

→ ANYONE on the internet can call this
→ No login needed
→ Complete data breach
```


## JWT/Token Manipulation ([[08.JWT (A07 Authentication Failures + A04 Cryptographic Failures)]])
```
Modifying JSON Web Tokens to escalate privileges

Example:
  JWT Payload: {"user":"john", "role":"user"}
  Tampered:    {"user":"john", "role":"admin"}
  
  Or changing algorithm to "none"
```

## Impact of Broken Access control
```
┌─────────────────────────────────────────┐
│           IMPACT                        │
├─────────────────────────────────────────┤
│ ⚠ Unauthorized data access             │
│ ⚠ Data theft / Data breach             │
│ ⚠ Account takeover                     │
│ ⚠ Modification/deletion of data        │
│ ⚠ Complete system compromise           │
│ ⚠ Compliance violations (GDPR, HIPAA)  │
│ ⚠ Financial loss                       │
│ ⚠ Reputation damage                    │
└─────────────────────────────────────────┘

CVSS Score: Usually HIGH to CRITICAL (7.0 - 9.8)
```