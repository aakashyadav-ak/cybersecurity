
#  Process States and Lifecycle

## Process?
A process is a running program.

When you open a program, it becomes a process.

**Examples:**
- You type ls → A process runs and shows files
- Firefox browser open → A process running
- Apache web server → A process running in background


#### Process vs Program

| Feature      | Program      | Process              |
| :----------- | :----------- | :------------------- |
| **Location** | File on disk | Running in memory    |
| **State**    | Static       | Active               |
| **Quantity** | One copy     | Can have many copies |
**Example:**
- /usr/bin/firefox = Program (file)
- Running Firefox = Process


#### Every Process Has
| Property     | Meaning                    | Example           |
| :----------- | :------------------------- | :---------------- |
| **PID**      | Process ID (unique number) | `1234`            |
| **PPID**     | Parent Process ID          | `1`               |
| **User**     | Who started it             | `john`            |
| **State**    | Current status             | Running, Sleeping |
| **CPU %**    | CPU usage                  | `5%`              |
| **Memory %** | RAM usage                  | `2%`              |

#### Process States
| State | Letter | Meaning |
| :--- | :--- | :--- |
| **Running** | `R` | Currently executing |
| **Sleeping** | `S` | Waiting for something |
| **Stopped** | `T` | Paused (Ctrl+Z) |
| **Zombie** | `Z` | Finished but not cleaned up |
| **Dead** | `X` | Completely finished |

#### Process Lifecycle
```
Created → Running → Sleeping → Running → Terminated
            ↑          ↓
            └──────────┘
```

**Simple flow:**
1. You start a program
2. It becomes a process (Running)
3. It may wait for input (Sleeping)
4. It continues (Running)
5. It finishes (Terminated)


### Parent and Child Processes

Every process has a parent (except PID 1).
```
init/systemd (PID 1)
    └── bash (PID 1000)
            └── ls (PID 1234)
```

**When you run a command:**
- Your shell (bash) is the parent
- The command becomes the child


#### View Process Information
```
ps
```

**Output:**
```
  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 1250 pts/0    00:00:00 ps
```

**All processes (full format):**

```
ps aux
```


##### Find Specific Process
```
ps aux | grep apache
ps aux | grep ssh
ps aux | grep python
```

##### View Process Tree
See parent-child relationships:
```
pstree
```