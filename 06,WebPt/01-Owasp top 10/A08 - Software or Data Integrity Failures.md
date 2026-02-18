Software or Data Integrity Failures happens when an application **trusts code, updates, or data** without verifying whether it was **modified or tampered with**.

>The application trusts external data, code, or updates without verifying they haven't been tampered with. Attackers can inject malicious code or manipulate data that the system blindly accepts.


> “Software/Data Integrity Failures occur when the application accepts untrusted code or data without validation, allowing attackers to inject malicious updates or manipulate important values.”


## Integrity
**Integrity = data should not be changed without authorization.**

So A08 is basically:
- The system is **unable to detect tampering**
- The system **trusts untrusted inputs too much**

## Examples:
### 1) Unsigned Updates / Untrusted Update Mechanism
If the app downloads updates/plugins and does not verify them using:
- signatures
- hashes
- trusted sources

```
❌ INSECURE: Auto-updater without signature verification

Update Flow:
  App checks: https://example.com/latest-version.exe
       ↓
  Downloads file directly
       ↓
  Executes without verifying source
       ↓
  Attacker intercepts (MITM) → delivers malware

Problem: No way to verify update came from legitimate source
```

Then attacker can:
- replace update file
- inject backdoor into update

**Example:**
- Desktop app auto-update over HTTP
- IoT firmware update without signature validation

### ==2) Insecure Deserialization== 
Serialization = converting object → data  
Deserialization = converting data → object

```
❌ INSECURE: Deserializing untrusted data

Attack Flow:
  User sends serialized object in cookie/request
       ↓
  Server deserializes without validation
       ↓
  Malicious object executes code during deserialization
       ↓
  Remote Code Execution (RCE)
```

If app deserializes user-controlled data, attacker can:
- execute code (RCE)
- change object values
- bypass authentication

📌 Common in:
- Java
- PHP
- .NET
- Python pickles


### 3) CDN Scripts Without Integrity Checking (No SRI)
Websites often load JS libraries from CDNs:

```html
<script src="https://cdn.com/jquery.js"></script>
```

If CDN gets compromised, attacker can inject JS and steal:
- session cookies
- tokens
- credentials

```
❌ BAD — External script without SRI

`<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>`

Problem:
  - CDN gets compromised
  - Attacker modifies jquery file
  - All websites using it now serve malware
  - No way to detect tampering
```

 **Best protection:**
- SRI (Subresource Integrity)
- CSP (Content Security Policy)

### Tampering of Important Client-Side Data

Some applications store sensitive logic in the client-side:
- price
- role
- discount
- permissions
- isAdmin flag

Attacker can modify request in Burp and change values.

**Example:**
```json
{
  "price": 1,
  "role": "admin"
}
```

If server trusts it → integrity failure.


## Impacts

- Malware/backdoor injection into app
- Account takeover (token/session theft via CDN JS)
- Privilege escalation (tampered role/permissions)
- Fraud (price/coupon tampering)
- Remote Code Execution (insecure deserialization)


## Testing Methodology

#### 1) Check for client-side trust issues

- Try modifying:
- price
- role
- discount
- userId
- status fields

#### 2) Identify external scripts

Check if scripts are loaded from:
- third-party CDNs
- unknown domains
- Check if integrity= is missing

#### 3) Check for deserialization patterns (basic)

Signs:
- base64 blobs
- serialized objects
- cookies with structured data

#### 4) Check update mechanisms (if applicable)

- Mobile apps
- desktop apps
- IoT portals
- plugin upload features