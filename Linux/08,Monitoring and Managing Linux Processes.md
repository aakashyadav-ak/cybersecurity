
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
| Property | Meaning | Example |
| :--- | :--- | :--- |
| **PID** | Process ID (unique number) | `1234` |
| **PPID** | Parent Process ID | `1` |
| **User** | Who started it | `john` |
| **State** | Current status | Running, Sleeping |
| **CPU %** | CPU usage | `5%` |
| **Memory %** | RAM usage | `2%` |