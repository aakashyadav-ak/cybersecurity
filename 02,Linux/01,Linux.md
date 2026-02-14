
# Linux
Linux is a **free and open-source operating system** based on Unix. It was created by **Linus Torvalds** in 1991.

## Key Components of Linux

### The Linux Architecture
```
┌─────────────────────────────────────┐
│         User Applications           │  Layer 4
├─────────────────────────────────────┤
│            Shell/CLI                │  Layer 3
├─────────────────────────────────────┤
│         System Libraries            │  Layer 2
├─────────────────────────────────────┤
│          Linux Kernel               │  Layer 1
├─────────────────────────────────────┤
│           Hardware                  │  Layer 0
└─────────────────────────────────────┘
```
### 1. Kernel
**The kernel manages:**

- **Process Management:** Scheduling, creation, termination
- **Memory Management:** RAM allocation, virtual memory
- **Device Drivers:** Hardware communication
- **System Calls:** Interface for applications
- **Security:** Access controls, permissions
  
```bash
  # Multiple ways to check kernel
uname -r                    # Kernel release
uname -a                    # All system info
```

### 2. Shell
- Command-line interface for interacting with the system
- Interprets and executes user commands
- Bash (Bourne Again Shell) is the default in RHEL
- Enables powerful scripting and automation

**Common Shells:**

| Shell    | Path        | Description        | VAPT Use           |
| :------- | :---------- | :----------------- | :----------------- |
| **Bash** | `/bin/bash` | Default RHEL shell | Scripting exploits |
| **Sh**   | `/bin/sh`   | POSIX shell        | Reverse shells     |
| **Zsh**  | `/bin/zsh`  | Enhanced shell     | Advanced features  |
| **Dash** | `/bin/dash` | Debian shell       | Minimal shells     |
```bash
# Check available shells
cat /etc/shells

# Current shell
echo $SHELL
echo $0

# Shell-specific configs (attack vectors)
~/.bashrc           # User bash config
~/.bash_history     # Command history (passwords!)
/etc/profile        # System-wide settings
/etc/bash.bashrc    # Global bash config
```

### 3. File System
- Hierarchical structure starting from / (root)
- Everything in Linux is treated as a file
- Directories, devices, sockets, processes are all files
- Case-sensitive naming

```bash
/                   # Root directory
├── /bin           # Essential user binaries
├── /boot          # Boot loader files
├── /dev           # Device files
├── /etc           # System configuration file ⚠️ 
├── /home          # User home directories
├── /lib           # Essential libraries
├── /media         # Removable media mount points
├── /mnt           # Temporary mount points
├── /opt           # Optional software
├── /proc          # Process information (virtual)
├── /root          # Root user home
├── /sbin          # System binaries
├── /srv           # Service data
├── /sys           # Kernel and system info (virtual)
├── /tmp           # Temporary files ⚠️ Often writable
├── /usr           # User programs
├── /var           # Variable data (logs, mail, etc.)
```

```bash
# Configuration files (credentials, settings)
/etc/passwd         # User accounts
/etc/shadow         # Password hashes
/etc/sudoers        # Sudo privileges
/etc/ssh/           # SSH configuration

# Logs (information disclosure)
/var/log/auth.log   # Authentication logs
/var/log/syslog     # System logs
/var/log/apache2/   # Web server logs

# Temporary (privilege escalation)
/tmp/               # World-writable
/var/tmp/           # Persistent temp
/dev/shm/           # Shared memory
```
### 4. Userspace
- All applications and utilities running outside kernel
- Includes system tools, libraries, and user programs


## What is a Distribution (Distro)

A Linux Distribution (distro) = Linux Kernel + GNU Tools + Package Manager + Desktop Environment + Pre-configured Software

A Linux distribution is a complete operating system built around the Linux kernel with:
- Package management system
- Default applications
- Desktop environment (optional)
- Configuration tools

```
Linux Distributions Family Tree
================================
         Debian Based                 RHEL Based               Others
         ────────────                 ──────────               ──────
         │                            │                        │
    ┌────┴────┐                  ┌────┴────┐            ┌─────┴─────┐
    │ Debian  │                  │  RHEL   │            │ Arch Linux│
    └────┬────┘                  └────┬────┘            └───────────┘
         │                            │                        │
    ┌────┴────┐                  ┌────┴────┐            ┌─────┴─────┐
    │ Ubuntu  │                  │ CentOS  │            │ Slackware │
    └────┬────┘                  └─────────┘            └───────────┘
         │                            │                        │
    ┌────┴────┐                  ┌────┴────┐            ┌─────┴─────┐
    │  Kali   │                  │ Fedora  │            │  Gentoo   │
    └─────────┘                  └─────────┘            └───────────┘
```

| Distro            | Base        | Use Case              |
| :---------------- | :---------- | :-------------------- |
| **RHEL**          | Independent | Enterprise servers    |
| **CentOS Stream** | RHEL        | Development/Testing   |
| **Rocky Linux**   | RHEL        | Free RHEL alternative |
| **Ubuntu**        | Debian      | Desktops/Servers      |
| **Kali Linux**    | Debian      | Penetration Testing   |
| **Fedora**        | Independent | Cutting-edge features |

**Package manager:**
Debian/Ubuntu= apt (file extension .deb)