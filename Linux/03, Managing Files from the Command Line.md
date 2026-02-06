# The Linux File System Structure
Linux uses a hierarchical (tree) structure starting from the root directory /. Unlike Windows which uses drive letters (C:, D:), Linux has a single unified tree.

```
/
├── bin
├── boot
├── dev
├── etc
├── home
├── lib
├── media
├── mnt
├── opt
├── proc
├── root
├── run
├── sbin
├── srv
├── sys
├── tmp
├── usr
└── var
```

| Directory | Purpose | VAPT Relevance |
| :--- | :--- | :--- |
| `/` | Root of file system | Starting point for enumeration |
| `/etc` | Configuration files | Passwords, configs, sensitive data |
| `/home` | User home directories | User data, SSH keys, history files |
| `/root` | Root user's home | High-value target |
| `/var` | Variable data (logs, mail) | Log analysis, evidence |
| `/tmp` | Temporary files | World-writable, exploit staging |
| `/opt` | Optional/third-party software | Installed applications |
| `/proc` | Process information (virtual) | Running processes, system info |
| `/dev` | Device files | Hardware access |
| `/bin` | Essential user binaries | Basic commands |
| `/sbin` | System binaries | Admin commands |
| `/usr` | User programs and data | Applications, libraries |
| `/var/log` | Log files | Attack evidence, troubleshooting |
| `/var/www` | Web server files | Web application files |