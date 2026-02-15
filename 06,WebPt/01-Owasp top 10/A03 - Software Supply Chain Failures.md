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
