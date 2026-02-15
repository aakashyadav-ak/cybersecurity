**Meaning:** Weak login, session, or identity handling allows attackers to take over accounts.  

“Authentication failures happen when the app does not properly protect login and session mechanisms.”


## Common Authentication Failures
### 1. Weak Password Policy

**The Problem:**
```
Website allows:
  - "password"
  - "123456"
  - "admin"
  - "qwerty"

These are in the TOP 10 most common passwords.
Attackers try these FIRST.
-> Easy brute force / guessing.
```

**Mitigation:**
- Minimum 12 characters (length > complexity)
- Check against known breached password lists
 - No common patterns ("Password123!")

### 2. No Multi-Factor Authentication (MFA)

**The Problem:**
```
Login process:
  Step 1: Enter password
  Step 2: You're in ✓

Attacker who steals/guesses password:
  Step 1: Enter password
  Step 2: They're in ✓

ONE barrier. That's it.
```

**Mitigation:**
Use MFA 
```
SOMETHING YOU KNOW:    Password, PIN
SOMETHING YOU HAVE:    Phone, hardware token
SOMETHING YOU ARE:     Fingerprint, face

Use at least TWO different categories.
```

### 3. Session Not Invalidated After Logout

**The Problem:**
```
User clicks "Logout"
  → Screen says "You're logged out"
  → But session token STILL WORKS
```

**How Attackers Exploit This:**
```
Scenario 1: Public Computer
  1. You log into email at library
  2. You click "Logout"
  3. You leave
  4. Session cookie still in browser
  5. Next person presses "Back" button
  6. They're logged in as YOU

Scenario 2: Stolen Token
  1. Attacker steals your session cookie
  2. You notice weird activity
  3. You log out immediately
  4. Attacker's stolen cookie STILL WORKS
  5. Logging out did nothing
```

**Mitigation:**
After Clicking logout:
- Delete session from server
- Delete session cookie from browser
- Mark session as invalid in database
 - Any use of old session token = rejected
