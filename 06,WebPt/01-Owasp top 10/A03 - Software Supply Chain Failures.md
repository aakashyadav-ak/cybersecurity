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
### 1. Dependency Poisoning (Fake Packages)
```
You need a library called:  "flask"

Attacker creates:           "flaask"  (typo)
                            "fl4sk"   (looks similar)
                            "python-flask" (sounds official)

A developer types the wrong name by mistake
  → installs the ATTACKER's code
  → malicious code runs on their machine
```

**Real world:** This happens on NPM (JavaScript) and PyPI (Python) constantly.

### 2. Hijacked Packages
```
Popular library with 8 million users
  ↓
Attacker steals the maintainer's password
  ↓
Publishes a new "update" with hidden malware
  ↓
Millions of apps auto-update
  ↓
All compromised silently 💀
```


### 3. Build Pipeline Attacks (CI/CD)

Your build pipeline is the system that takes your code and turns it into a running app.

```

```