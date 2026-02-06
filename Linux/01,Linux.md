
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

- Process Management: Scheduling, creation, termination
- Memory Management: RAM allocation, virtual memory
- Device Drivers: Hardware communication
- System Calls: Interface for applications
- **Security:** Access controls, permissions

### 2. Shell
- Command-line interface for interacting with the system
- Interprets and executes user commands
- Bash (Bourne Again Shell) is the default in RHEL
- Enables powerful scripting and automation

### 3. File System
- Hierarchical structure starting from / (root)
- Everything in Linux is treated as a file
- Directories, devices, sockets, processes are all files
- Case-sensitive naming

### 4. Userspace
- All applications and utilities running outside kernel
- Includes system tools, libraries, and user programs


## What is a Distribution (Distro)
A Linux distribution is a complete operating system built around the Linux kernel with:

- Package management system
- Default applications
- Desktop environment (optional)
- Configuration tools


| Distro            | Base        | Use Case              |
| :---------------- | :---------- | :-------------------- |
| **RHEL**          | Independent | Enterprise servers    |
| **CentOS Stream** | RHEL        | Development/Testing   |
| **Rocky Linux**   | RHEL        | Free RHEL alternative |
| **Ubuntu**        | Debian      | Desktops/Servers      |
| **Kali Linux**    | Debian      | Penetration Testing   |
| **Fedora**        | Independent | Cutting-edge features |