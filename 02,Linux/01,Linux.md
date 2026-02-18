
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

```
┌──────────────────────────────────────────────────────────┐
│  User Applications (Layer 4)                             │
│  Examples:                                               │
│   • Firefox, Chrome                                      │
│   • VS Code                                              │
│   • Nmap, Wireshark                                      │
│   • Python apps, Docker, PostgreSQL                      │
├──────────────────────────────────────────────────────────┤
│  Shell / CLI (Layer 3)                                   │
│  Examples:                                               │
│   • bash, zsh, fish                                      │
│   • Commands: ls, cd, grep, chmod, ssh, curl             │
│   • Scripts: .sh files                                   │
├──────────────────────────────────────────────────────────┤
│  System Libraries (Layer 2)                              │
│  Examples:                                               │
│   • glibc (GNU C library)                                │
│   • OpenSSL (crypto/TLS)                                 │
│   • libpthread (threads)                                 │
│   • libpcap (packet capture)                             │
├──────────────────────────────────────────────────────────┤
│  Linux Kernel (Layer 1)                                  │
│  Examples:                                               │
│   • Process scheduling (runs programs)                   │
│   • Memory management (RAM, paging)                      │
│   • Networking stack (TCP/IP)                            │
│   • Filesystems (ext4, btrfs)                            │
│   • Drivers (Wi-Fi, GPU, USB)                            │
├──────────────────────────────────────────────────────────┤
│  Hardware (Layer 0)                                      │
│  Examples:                                               │
│   • CPU, RAM, SSD/HDD                                    │
│   • Network card (NIC)                                   │
│   • GPU, keyboard, mouse                                 │
└──────────────────────────────────────────────────────────┘

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
A shell is the program that lets you talk to the operating system using commands.

**It’s basically a command interpreter:**
```bash
ls
```
The shell understands it, and tells the OS:
- “Hey, list the files in this folder.”
- Then it prints the result back to you.

**Uses:**
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
A filesystem is how Linux stores and organizes data on disk (SSD/HDD/USB).

**It controls:**
- folders + files structure
- file permissions (read/write/execute)
- where system files live
- how devices get mounted

#### **/ (root)**
The top of everything. Every folder starts from here.

- Hierarchical structure starting from / (root)
- Everything in Linux is treated as a file
- Directories, devices, sockets, processes are all files
- Case-sensitive naming

#### **/home**
Where user files live.

**Example:**
- /home/username/Documents
- /home/username/Downloads

#### **/root**
Home folder for the root user (admin).

#### /etc
System configuration files.

**Examples:**
- /etc/passwd
- /etc/ssh/sshd_config
- /etc/hosts

#### /bin and /usr/bin
Essential commands and programs./ Essential user binaries

**Examples:**
- ls
- cat
- bash
- python3

#### /sbin and /usr/sbin
Admin/system commands.

**Examples:**
- iptables
- ifconfig (sometimes)
- system tools

#### /var
“Variable” data (logs, cache, changing stuff)

**Examples:**
- /var/log/auth.log
- /var/log/syslog

#### /tmp
Temporary files (often cleared on reboot)/Often writable
==every user can work in this directory==

#### /dev
Devices treated like files./Device files

**Examples:**
- /dev/sda (disk)
- /dev/null
- /dev/tty

#### /mnt and /media
Where drives get mounted (USB, external disks)


#### /proc
Virtual filesystem showing running system info.

**Examples:**
- /proc/cpuinfo
- /proc/meminfo


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



## Hidden Files

Files starting with . are hidden.
Example:
`.bashrc`
`.ssh/`

```bash
ls -la
```