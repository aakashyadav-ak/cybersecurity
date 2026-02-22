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


