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

