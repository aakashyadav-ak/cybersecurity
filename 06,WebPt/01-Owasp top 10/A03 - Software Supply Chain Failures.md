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


## Attack Vectors 
