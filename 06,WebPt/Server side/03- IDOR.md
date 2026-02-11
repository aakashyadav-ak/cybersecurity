# 1. IDOR(Insecure Direct Object Reference)(server side)

- IDOR occurs when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example database records or+ files.

- ==Attacker accesses unauthorized resources by manipulating object identifiers(ID of user,filename,etc).==

- Application exposes internal object references (IDs, filenames, keys) that attacker can manipulate to access other users' data. 


```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              IDOR TYPES                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. URL-Based IDOR                                                         │
│      ├── /api/user/123/profile                                              │
│      ├── /order/456/details                                                 │
│      ├── /invoice/789/download                                              │
│      └── Test: Change 123 → 456 in URL path                                 │
│                                                                             │
│   2. Body Parameter IDOR                                                    │
│      ├── JSON:  { "user_id": 123, "action": "view" }                        │
│      ├── Form:  user_id=123&action=update                                   │
│      ├── XML:   <userId>123</userId>                                        │
│      └── Test: Modify ID value in request body                              │
│                                                                             │
│   3. Cookie-Based IDOR                                                      │
│      ├── Plain:   Cookie: user_id=123                                       │
│      ├── Encoded: Cookie: user_id=MTIz (Base64)                             │
│      ├── JSON:    Cookie: user={"id":123}                                   │
│      └── Test: Edit cookie value in browser/Burp                            │
│                                                                             │
│   4. Header-Based IDOR                                                      │
│      ├── X-User-ID: 123                                                     │
│      ├── X-Account-ID: ACC001                                               │
│      ├── X-Customer-ID: 456                                                 │
│      └── Test: Modify or add custom headers                                 │
│                                                                             │
│   5. File Reference IDOR                                                    │
│      ├── /download?file=user_123_report.pdf                                 │
│      ├── /docs?name=invoice_456.pdf                                         │
│      ├── /export?id=backup_789.zip                                          │
│      └── Test: Guess other users' filenames                                 │
│                                                                             │
│   6. Query Parameter IDOR                                                   │
│      ├── /profile?id=123                                                    │
│      ├── /account?user=456&action=view                                      │
│      ├── /api/data?userId=789                                               │
│      └── Test: Change parameter value in URL                                │
│                                                                             │
│   7. Hash/Encoded IDOR                                                      │
│      ├── /user/MTIz (Base64 of "123")                                       │
│      ├── /doc/202cb962ac59... (MD5 of "123")                                │
│      ├── /profile/7b226964223a3132337d (Hex encoded)                        │
│      └── Test: Decode → Modify → Re-encode                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────┐
│                  WHERE TO FIND IDOR                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   URL Parameters:                                               │
│   ├── /user/123/profile                                         │
│   ├── /order/456/details                                        │
│   ├── /invoice/789/download                                     │
│   └── /message/101/view                                         │
│                                                                 │
│   Query Parameters:                                             │
│   ├── ?user_id=123                                              │
│   ├── ?account=456                                              │
│   ├── ?doc_id=789                                               │
│   └── ?transaction=101                                          │
│                                                                 │
│   Request Body:                                                 │
│   ├── { "id": 123 }                                             │
│   ├── { "user_id": 456 }                                        │
│   └── { "order_id": 789 }                                       │
│                                                                 │
│   Headers:                                                      │
│   ├── X-User-ID: 123                                            │
│   └── X-Account-ID: 456                                         │
│                                                                 │
│   Cookies:                                                      │
│   └── user_id=123; account=456                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Real Life Testing
1. **Create Two Accounts:** Create User A (Attacker) and User B (Victim).
2. **Identify IDs:** Look for predictable IDs in requests (e.g., user_id=1001, invoice_id=55).
3. **Capture Request:** Log in as User A and perform an action (e.g., View Profile).
4. **Swap IDs:** Send the request to Repeater and change the ID to User B's ID.
**Analyse Response:**
- 200 OK + Data = Vulnerable
- 403 Forbidden = Secure (usually)
- 401 Unauthorized = Not logged in
#### Example 1: Bank Account Access
```
# Normal Request (User's own account)
GET /api/account/1001/balance
Authorization: Bearer <token>

Response: { "balance": "$5,000" }

# IDOR Attack (Other user's account)
GET /api/account/1002/balance
Authorization: Bearer <token>

Response: { "balance": "$50,000" }  # Unauthorized access!
```

#### Example 2: Password Reset IDOR
```
# Normal Request
POST /api/reset-password
{ "user_id": 123, "new_password": "newpass123" }

# IDOR Attack
POST /api/reset-password
{ "user_id": 456, "new_password": "hacked123" }  # Reset other user's password!
```

#### Real-World IDOR Examples

| Company       | What Happened        | Impact                     |
| :------------ | :------------------- | :------------------------- |
| **Facebook**  | IDOR in photo albums | View private photos        |
| **Uber**      | IDOR in trip history | Access other riders' trips |
| **Shopify**   | IDOR in admin panel  | Access other stores' data  |
| **Instagram** | IDOR in media ID     | Delete any user's photos   |
| **Twitter**   | IDOR in DMs          | Read private messages      |

**ID Manipulation Techniques**
```
# Sequential IDs
/user/100 → /user/101, /user/102, /user/99

# UUID Guessing (if predictable)
/user/550e8400-e29b-41d4-a716-446655440000
→ /user/550e8400-e29b-41d4-a716-446655440001

# Encoded IDs
/user/MTIz (base64 of "123") → /user/NDU2 (base64 of "456")

# Hashed IDs (if weak)
/user/202cb962ac59075b964b07152d234b70 (MD5 of "123")
→ /user/250cf8b51c773f3f8dc8b4be867a9a02 (MD5 of "456")

# Wrapped IDs
/user/{"id":123} → /user/{"id":456}
```

## Mitigation
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          IDOR MITIGATIONS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. Verify Ownership on Every Request                                      │
│      ├── Always check if user owns the resource                             │
│      ├── Don't trust client-provided IDs                                    │
│      └── Use server-side session for user identity                          │
│                                                                             │
│   2. Use Indirect Object References                                         │
│      ├── Map real IDs to random tokens per session                          │
│      ├── User sees: abc123xyz                                               │
│      └── Server resolves: abc123xyz → real ID 456                           │
│                                                                             │
│   3. Use UUIDs Instead of Sequential IDs                                    │
│      ├── Bad:  /user/1, /user/2, /user/3                                    │
│      └── Good: /user/550e8400-e29b-41d4-a716-446655440000                   │
│                                                                             │
│   4. Implement Proper Access Control                                        │
│      ├── Role-Based Access Control (RBAC)                                   │
│      ├── Attribute-Based Access Control (ABAC)                              │
│      └── Check permissions at every endpoint                                │
│                                                                             │
│   5. Validate at Database Query Level                                       │
│      ├── Bad:  SELECT * FROM orders WHERE id = ?                            │
│      └── Good: SELECT * FROM orders WHERE id = ? AND user_id = ?            │
│                                                                             │
│   6. Logging & Monitoring                                                   │
│      ├── Log all access attempts                                            │
│      ├── Alert on suspicious patterns                                       │
│      └── Monitor for enumeration attacks                                    │
│                                                                             │
│   7. Rate Limiting                                                          │
│      ├── Limit requests per user/IP                                         │
│      └── Prevents mass ID enumeration                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**example:**
```
// ❌ VULNERABLE - No ownership check
app.get('/api/order/:id', (req, res) => {
    const order = db.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
    res.json(order);
});

// ✅ SECURE - Ownership verification
app.get('/api/order/:id', authenticateToken, (req, res) => {
    const order = db.query(
        'SELECT * FROM orders WHERE id = ? AND user_id = ?', 
        [req.params.id, req.user.id]  // Added user_id check
    );
    
    if (!order) {
        return res.status(404).json({ error: 'Not found' });
    }
    
    res.json(order);
});
```