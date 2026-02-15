**Meaning:** Security risks coming from third-party libraries, dependencies, build systems, and CI/CD pipeline.  

Even if our code is secure, a compromised dependency or pipeline can compromise the whole application.

Supply chain attacks target the trust relationships between your application and everything it depends on — libraries, build tools, CI/CD pipelines, container images, and third-party scripts. Instead of attacking your code directly, adversaries compromise something your code consumes.
```
Your Application
    ├── Direct dependency (trusted?)
    │     └── Transitive dependency (who even audited this?)
    ├── Build pipeline (CI/CD)
    │     ├── GitHub Actions / Jenkins plugins
    │     └── Environment secrets
    ├── Container base images
    └── Third-party CDN scripts
          └── ← attacker compromises HERE
```

```
Your App
  ├── Someone else's login library
  ├── Someone else's database tool
  ├── Someone else's image uploader
  ├── Someone else's payment code
  └── Someone else's build tools

You didn't write 90% of your app.
You TRUST that other people's code is safe.
```

**Supply chain attack** = someone poisons one of those suppliers.




## Attack Vectors

### 1) Vulnerable / Outdated Dependencies (Most common)
**Meaning:** The application uses old libraries with known CVEs.

**Example:**
- Old `jQuery` with XSS issues
- Old `Struts` with RCE
- Old `Log4j` (Log4Shell)

**Why it matters:**
Even if your app code is safe, the library itself can be exploited.

---

### 2) Dependency Poisoning / Typosquatting
**Meaning:** Developer installs the wrong package because attacker created a similar name.

**Example:**
- Real package: `requests`
- Attacker package: `reqeusts` (spelling trick)
  
```
  You need a library called:  "flask"

Attacker creates:           "flaask"  (typo)
                            "fl4sk"   (looks similar)
                            "python-flask" (sounds official)

A developer types the wrong name by mistake
  → installs the ATTACKER's code
  → malicious code runs on their machine
```

**Why it matters:**
The fake package can contain malware/backdoor.

---

### 3) Compromised NPM/PyPI/Maven Package
**Meaning:** A real popular package gets hacked and attacker injects malicious code into it.

**Example:**
- A legit NPM package update suddenly starts stealing tokens.

**Why it matters:**
Thousands of apps auto-update and get infected.

---

### 4) Secrets Leaked in CI/CD
**Meaning:** DevOps pipelines store secrets in plain text.

**Examples:**
- GitHub Actions contains AWS keys
- Jenkins config contains API token
- `.env` file pushed in repo

**Why it matters:**
Attackers can use leaked keys to access cloud, DB, storage.

---

### 5) Insecure CI/CD Pipeline
**Meaning:** Attackers can modify the build process and inject malicious code into production.

**Examples:**
- Jenkins exposed to internet with weak password
- GitHub repo compromised → malicious code merged

**Why it matters:**
This becomes a *trusted* backdoor shipped to all users.

---

### 6) Untrusted Third-Party Scripts (CDN Risk)
**Meaning:** Website loads JavaScript from external domains.

**Example:**
```html
<script src="http://randomcdn.com/lib.js"></script>
```

## Impacts
```
A supply chain attack doesn't hit ONE app.
It hits EVERYONE who uses that compromised piece.

  One poisoned library
      ↓
  Downloaded by 10,000 companies
      ↓
  Running on millions of machines
      ↓
  ALL compromised at once
```


### Data Theft
```
What attackers steal through supply chain attacks:

  ├── Customer personal data (names, emails, addresses)
  ├── Credit card numbers
  ├── Login passwords
  ├── API keys and secrets
  ├── Internal business documents
  ├── Database contents
  └── Encryption keys

All done SILENTLY through code you trusted.
```
### Complete System Takeover
```
When you install a library, it runs with YOUR permissions.

  Your app can read the database?
      → The malicious library can too.

  Your app can access user data?
      → The malicious library can too.

  Your build server has deployment keys?
      → The malicious library can steal them.

There is NO sandbox. NO restriction.
It has the SAME power as your own code.
```
### Silent and Long-Lasting Access
```
Most attacks are LOUD:
  - Website goes down
  - Data gets deleted
  - You KNOW something is wrong

Supply chain attacks are QUIET:

  Day 1:    Malicious update installed       ← looks normal
  Day 30:   Attacker exploring your systems  ← you don't know
  Day 90:   Attacker stealing data slowly    ← still no clue
  Day 180:  Someone finally notices          ← 6 months too late

  Average detection time: 250+ days
```



## Mitigation

# 1) Dependency Management Controls (Most Important)

##  Use trusted sources only
- Use official package registries:
  - npmjs.com
  - pypi.org
  - Maven Central
- Avoid random GitHub ZIP downloads.

## Pin dependency versions
- Lock versions using:
  - `package-lock.json`
  - `yarn.lock`
  - `poetry.lock`
  - `requirements.txt` with exact versions

**Why:** prevents auto-installing malicious updates.

---

#  2) Dependency Scanning (SCA)

##  Perform Software Composition Analysis (SCA)
Tools:
- OWASP Dependency-Check
- Snyk
- GitHub Dependabot
- Trivy
- npm audit / pip-audit

**What it finds:**
- vulnerable packages
- known CVEs
- outdated versions

##  Patch regularly
- Create patch cycles:
  - monthly for normal
  - immediate for critical CVEs

---

# 4) Secure CI/CD Pipeline (Super Critical)

##  Protect CI/CD access
- Strong authentication
- MFA for DevOps accounts
- Limit who can modify pipelines

##  Use least privilege
- CI runner should have minimum permissions.
- Build system should not have admin access.

##  Separate environments
- Build server ≠ production server
- CI should not have direct production SSH access

##  Protect pipeline configs
- Restrict modification of:
  - `.github/workflows/`
  - Jenkinsfiles
  - GitLab pipelines

---

#  5) Secrets Management 

##  Never store secrets in code
Do NOT hardcode:
- API keys
- DB passwords
- AWS access keys
- JWT secrets

##  Use secret managers
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- GCP Secret Manager

##  Rotate secrets frequently
- Especially if leaked once.

##  Enable secret scanning
Tools:
- GitHub secret scanning
- TruffleHog
- Gitleaks
