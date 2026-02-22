# 1: Email Headers Basics

### Email Header Structure
```
Headers are read BOTTOM to TOP (oldest → newest)

┌─────────────────────────────────────────┐
│ To: victim@company.com                  │ ← Recipient
│ From: ceo@company.com                   │ ← Claimed sender (can be spoofed!)
│ Subject: Urgent Wire Transfer           │
│ Date: Mon, 15 Mar 2024 10:23:45         │
│ Message-ID: <abc123@mail.com>           │
│ X-Originating-IP: 45.142.212.61         │ ← Real sender IP
│ Received: from mail.evil.com            │ ← Mail servers path
│ Authentication-Results: spf=fail        │ ← SPF/DKIM/DMARC results
└─────────────────────────────────────────┘
```



#### Key Headers to Analyze

| Header                   | What It Shows            | Why Important                          |
|--------------------------|--------------------------|----------------------------------------|
| From                     | Claimed sender           | Can be spoofed                         |
| Reply-To                 | Where replies go         | Often different in phishing            |
| Return-Path              | Bounce address           | Helps identify real sending domain     |
| Received                 | Mail server path         | Used to trace email origin             |
| X-Originating-IP         | Sender's real IP         | Helps identify attacker infrastructure |
| Authentication-Results   | SPF/DKIM/DMARC status    | Verifies sender legitimacy             |

____

# 2: SPF / DKIM / DMARC
## The Email Authentication Trinity
```
SPF  → Who can SEND for this domain?
DKIM → Is the email AUTHENTIC (not modified)?
DMARC → What to DO if SPF/DKIM fails?
```


### SPF (Sender Policy Framework)

```
PURPOSE: Verify sender IP is authorized

HOW IT WORKS:
1. Email claims to be from: company.com
2. Receiver checks: company.com's SPF record
3. SPF record says: "Only these IPs can send for us"
4. If sender IP matches → PASS ✅
5. If sender IP doesn't match → FAIL ❌
```

**SPF Results:**

## SPF (Sender Policy Framework) Results Explained

| Result        | Meaning                    | Action                |
|--------------|----------------------------|-----------------------|
| spf=pass     | Authorized sender ✅       | Likely legitimate     |
| spf=fail     | Unauthorized sender ❌     | Likely spoofed        |
| spf=softfail | Probably unauthorized      | Suspicious            |
| spf=neutral  | No explicit allow/deny     | Cannot verify         |
| spf=none     | No SPF record found        | Cannot verify         |

### DKIM (DomainKeys Identified Mail)

```
PURPOSE: Verify email wasn't modified in transit

HOW IT WORKS:
1. Sending server signs email with private key
2. Signature added to header
3. Receiver gets public key from DNS
4. Receiver verifies signature
5. If signature valid → PASS ✅
6. If signature invalid → FAIL ❌
```

**DKIM Results:**

| Result     | Meaning                                   |
|------------|--------------------------------------------|
| dkim=pass  | Email authentic, not modified ✅           |
| dkim=fail  | Email modified or forged ❌                |
| dkim=none  | No DKIM signature present                 |


### DMARC (Domain-based Message Authentication)
```
PURPOSE: Tell receivers what to do if SPF/DKIM fail

HOW IT WORKS:
1. Domain publishes DMARC policy
2. Policy says: "If SPF/DKIM fail, do X"
3. X can be: none, quarantine, or reject
```

**DMARC Policies:**

| Policy        | Action                          |
|--------------|----------------------------------|
| p=none       | Monitor only, no action          |
| p=quarantine | Send to spam folder              |
| p=reject     | Block the email completely       |

**DMARC Results:**
Result	                             Meaning
dmarc=pass                  	Email passed authentication ✅
dmarc=fail                    	Email failed authentication ❌


____

# 3: Extract Sender IP & Identify Spoofing
