
#  Command Line
The command line (also called terminal, console, or shell) is a text-based interface to interact with the Linux operating system. Instead of clicking icons, you type commands.

- Faster than GUI for repetitive tasks
- Can be scripted and automated
- Works over remote connections (SSH)
- Many security tools are CLI-only
- Less resource intensive
- Available on all Linux systems including servers


## Accessing the Command Line

### 1. Physical Console
- Direct keyboard and monitor connection
- Used for server rooms and local access
- Login prompt appears after boot

### 2. Virtual Consoles (TTY)
- RHEL provides multiple virtual consoles
- Switch between them using keyboard shortcuts
- Ctrl + Alt + F1 to F6 for text consoles
- Ctrl + Alt + F1 or F2 usually returns to GUI (if installed)

### 3. Terminal Emulator (GUI)
- Application within desktop environment
- GNOME Terminal is default in RHEL
- Access via Applications menu or right-click desktop

### 4. Remote Access (SSH)
- Secure Shell protocol
- Access from another machine over network
- Most common method for servers
- Command: ssh username@hostname


#### After login, you see the shell prompt:
```
[user@hostname ~]$
```

| Part       | Meaning                            |
| :--------- | :--------------------------------- |
| `user`     | Current username                   |
| `@`        | Separator                          |
| `hostname` | System name                        |
| `~`        | Current directory (`~` means home) |
| `$`        | Regular user prompt                |
| `#`        | **Root** user prompt               |

```
[john@server1 ~]$        # Regular user john in home directory
[root@server1 /etc]#     # Root user in /etc directory
[admin@webserver logs]$  # User admin in logs directory
```

---

#  Execute Commands with the Bash Shell
Bash (Bourne Again Shell) is the default shell in RHEL. 
- Interprets and executes commands
- Provides scripting capabilities
- Maintains command history
- Supports tab completion
- Allows command chaining and redirection


#### Basic Command Structure
```
command [options] [arguments]
```

| Component | Description | Example |
| :--- | :--- | :--- |
| **Command** | The program to run | `ls` |
| **Options** | Modify behavior (start with `-` or `--`) | `-l`, `--help` |
| **Arguments** | What the command acts on | `/etc` |

```
ls                      # Command only
ls -l                   # Command + option
ls /etc                 # Command + argument
ls -la /etc             # Command + options + argument
```

## Essential Commands 
#### 1. Navigation Commands

| Command | Purpose | Example |
| :--- | :--- | :--- |
| **pwd** | Print working directory | `pwd` |
| **cd** | Change directory | `cd /var/log` |
| **ls** | List directory contents | `ls -la` |
#### cd shortcut
```
cd          # Go to home directory
cd ~        # Go to home directory
cd -        # Go to previous directory
cd ..       # Go up one directory
cd ../..    # Go up two directories
```

#### System Information Commands

| Command               | Purpose            | VAPT Use                  |
| :-------------------- | :----------------- | :------------------------ |
| `whoami`              | Current username   | Identify compromised user |
| `id`                  | User and group IDs | Check privileges          |
| `hostname`            | System name        | Identify target           |
| `uname -a`            | Kernel info        | Find kernel exploits      |
| `cat /etc/os-release` | OS version         | Identify target OS        |

#### User Information Commands