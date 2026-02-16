In penetration testing and red teaming, transferring files between systems is crucial for:

- Uploading tools to target systems
- Exfiltrating data from compromised hosts
- Moving laterally across networks
- Establishing persistence


## SSH File Transfers
SSH = Secure Shell - encrypted way to connect and transfer files between computers

### SCP (Secure Copy) - The Easiest Way
Think of SCP like "copy-paste" between computers over SSH.

**Basic Format:**
```bash
scp [source] [destination]
```