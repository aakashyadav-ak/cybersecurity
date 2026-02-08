
# SSH = Secure Shell

SSH lets you:

- Connect to remote computers securely
- Run commands on remote systems
- Transfer files securely
- All communication is encrypted



## Access the Remote Command Line with SSH

### Basic SSH Connection
**Syntax:**
```
ssh username@hostname
```

**example:**
```
ssh john@192.168.1.100
ssh root@server.example.com
ssh admin@10.0.0.5
```

#### First Time Connection
When connecting to a new server:
```
ssh john@192.168.1.100
```

**Output:**
```
The authenticity of host '192.168.1.100' can't be established.
ECDSA key fingerprint is SHA256:abc123xyz...
Are you sure you want to continue connecting (yes/no)?
```
Type yes and press Enter.

This saves the server's fingerprint to ~/.ssh/known_hosts.


## SSH with Different Port
Default SSH port is 22.

If server uses different port:
```
ssh -p 2222 john@192.168.1.100
```

## ssh -p 2222 john@192.168.1.100
```
ssh -v john@192.168.1.100      # Verbose
ssh -vv john@192.168.1.100     # More verbose
ssh -vvv john@192.168.1.100    # Most verbose
```


___

# Configure SSH Key-based Authentication

## Use of SSH Keys

| Feature | Password Login | Key-based Login |
| :--- | :--- | :--- |
| **User Experience** | Type password every time | No password needed |
| **Security Risk** | Can be brute-forced | ✅ Much more secure |
| **Weakness** | Easy to guess weak passwords | Keys are very long |

#### How Key Authentication Works
```
1. You have: Private Key (secret) + Public Key (share it)
2. Server has: Your Public Key in authorized_keys
3. You connect → Server challenges you
4. Your Private Key proves your identity
5. Access granted!
```

