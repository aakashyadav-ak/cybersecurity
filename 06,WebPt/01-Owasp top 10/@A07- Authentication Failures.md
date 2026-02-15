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

### 4. Session Fixation

**The Problem:**
```
Normal flow:
  1. User logs in
  2. Server creates NEW session ID
  3. User gets that session ID

Vulnerable flow:
  1. Server gives session ID BEFORE login
  2. User logs in
  3. Server keeps THE SAME session ID
  
Attacker can SET the session ID before you log in.
```

**The Attack:**
```
Step 1: Attacker gets a session ID from the site
  → Session ID: ABC123

Step 2: Attacker tricks YOU into using that session
  → Sends link: example.com?sessionid=ABC123
  → Or sets cookie on shared computer

Step 3: YOU log in with that session ID
  → Server authenticates you
  → But keeps session ID: ABC123

Step 4: Attacker uses ABC123
  → They're logged in as YOU
  → You did the authentication for them
```

**Mitigation:**
- Generate NEW session ID after successful login
- Invalidate old session ID completely
- Never accept session IDs from URL parameters
- Regenerate session on privilege changes

### 5. Predictable Session IDs
### 6. No Account Lockout
```
Attacker tries passwords:
  attempt 1:  password     ✗
  attempt 2:  123456       ✗
  attempt 3:  admin        ✗
  attempt 100: qwerty      ✗
  attempt 1000: password1  ✓ SUCCESS

No limit on attempts = attacker has INFINITE tries
```

### 7. Exposing Session IDs in URLs
### 8. Long Session Timeouts
```
Bank session active for: 5 minutes    ✅
Email session active for: 2 weeks     ⚠️
Shopping session for: Never expires   ❌

Longer session = longer window for theft
```


### 9. No Rate Limiting on Login
```
Without rate limiting:
  Attacker makes 10,000 login attempts per second
  Tests millions of passwords quickly

With rate limiting:
  After 5 failed attempts → wait 1 minute
  Makes brute force impractical
```