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

#### Download file from target to Kali (SCP)

```bash
scp user@<target-ip>:/path/file.txt .
```


#### Upload file from Kali to target
```
scp payload.sh user@<target-ip>:/tmp/

```


### SFTP (Interactive File Transfer)
Like FTP but secure. Good when you want to browse and select files.

```bash
# Connect to remote computer
sftp username@192.168.1.100

# Now you're in an SFTP session
sftp> ls                    # See remote files
sftp> lls                   # See local files
sftp> get remotefile.txt    # Download file
sftp> put localfile.txt     # Upload file
sftp> bye                   # Exit
```


___

## Python File Transfers

### Method 1: Python HTTP Server (Most Common)

**On the computer SHARING files (Server):**
```bash
# Go to folder with files
cd /path/to/files

# Start simple web server
python3 -m http.server 8000
```

Now anyone can download files by visiting: `http://YOUR_IP:8000`

**On the computer DOWNLOADING files (Client):**
```bash
# Download using wget
wget http://192.168.1.100:8000/file.txt

# Or using curl
curl http://192.168.1.100:8000/file.txt -o file.txt
```