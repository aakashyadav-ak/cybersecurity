Insecure Design is about flaws in the architecture and business logic — problems that cannot be fixed by perfect code implementation because the design itself is fundamentally flawed.

**Meaning:** The application’s *design/logic* is insecure, so attackers can abuse it even if there is no technical bug.  

 “Insecure design is when security controls are missing at design level, like no rate limit, weak reset flow, or broken business logic.”

```
Insecure Design ≠ Insecure Implementation

┌─────────────────────────────────────────────────┐
│           INSECURE DESIGN (A06)                 │
│  "We never planned for this attack scenario"    │
│  → No amount of clean code fixes this           │
│  → Requires architectural redesign              │
├─────────────────────────────────────────────────┤
│        INSECURE IMPLEMENTATION (other cats)     │
│  "We planned correctly but coded it wrong"      │
│  → Fix the bug, design remains sound            │
└─────────────────────────────────────────────────┘
```

## Examples
####  1) No Rate Limiting (Design flaw)
- Unlimited login attempts
- Unlimited OTP attempts
- Unlimited password reset requests

**Outcome:** Bruteforce / OTP guessing / account takeover.

#### 2) Weak Password Reset Design
- Reset token never expires
- Reset token reusable
- Reset token predictable
- Reset link not tied to user/session

**Outcome:** Account takeover.

#### 3) OTP Reuse / Unlimited OTP Attempts
- OTP valid for long time
- Same OTP works multiple times
- No attempt limit
- OTP not tied to transaction

**Outcome:** OTP bypass, takeover, payment abuse.

#### 4) Business Logic Flaws (Most common in real apps)
- Change product price in request
- Apply coupon multiple times
- Bypass payment and still get order confirmed
- Cancel order after delivery
- Refund without returning item

**Outcome:** Financial loss + fraud.

---

#### 5) Missing Abuse Controls
- No CAPTCHA on sensitive actions
- No anti-automation controls
- No lockout policy

**Outcome:** Bots can abuse the system.

---

#### 6) Trusting Client-Side Controls
- Role controlled by hidden field
- Discount controlled by request parameter
- “Admin=true” in JSON

**Outcome:** Privilege escalation / fraud.


## Testing
1. Try repeating login attempts (rate limiting)
2. Try OTP brute force (only if scope allows)
3. Test reset token expiry + reuse
4. Modify request values (price, role, quantity)
5. Try workflow bypass (skip steps)

## Impact
- Account takeover
- Fraud / financial loss
- Privilege escalation
- Data manipulation

## Mitigation
| Issue               | Mitigation                                      |
| ------------------- | ----------------------------------------------- |
| No rate limiting    | Add request throttling + account lockout        |
| Weak password reset | Use random tokens + short expiry + single-use   |
| OTP flaws           | 6+ digits + max 3 attempts + expire in 5 min    |
| Business logic      | Validate all logic server-side, never trust client |
| No threat model     | Write abuse stories before coding               |
