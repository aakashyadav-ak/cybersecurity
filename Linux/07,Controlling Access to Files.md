# Interpret Linux File System Permissions

## Permissions

**Permissions control:**
- Who can read a file
- Who can write (edit) a file
- Who can run (execute) a file


### Three Permission Types
| Permission  | Letter | For Files      | For Directories            |
| :---------- | :----- | :------------- | :------------------------- |
| **Read**    | `r`    | View content   | List files inside          |
| **Write**   | `w`    | Edit content   | Create/delete files inside |
| **Execute** | `x`    | Run as program | Enter the directory        |

### Three User Categories

| Category | Meaning |
| :--- | :--- |
| **Owner** (`u`) | The user who owns the file |
| **Group** (`g`) | Users in the file's group |
| **Others** (`o`) | Everyone else |

### View Permissions
```
ls -l
```

**output:**
```
-rw-r--r--. 1 john developers 1024 Jan 15 10:30 myfile.txt
```

```
-rw-r--r--. 1 john developers 1024 Jan 15 10:30 myfile.txt
│└──┴──┴──┘    │    │
│   │  │  │    │    └── Group owner
│   │  │  │    └─────── User owner
│   │  │  └──────────── Others permissions (r--)
│   │  └─────────────── Group permissions (r--)
│   └────────────────── Owner permissions (rw-)
└────────────────────── File type (- = file)
```


#### File Type (First Character)
| Character | Meaning          |
| :-------- | :--------------- |
| `-`       | Regular file     |
| `d`       | Directory        |
| `l`       | Symbolic link    |
| `c`       | Character device |
| `b`       | Block device     |
#### Reading Permissions
```
-rw-r--r--
```

| Part  | Characters | Meaning                            |
| :---- | :--------- | :--------------------------------- |
| **1** | `-`        | File type (regular file)           |
| **2** | `rw-`      | Owner can read, write, not execute |
| **3** | `r--`      | Group can read only                |
| **4** | `r--`      | Others can read only               |

#### Permission Examples
| Permission | Meaning |
| :--- | :--- |
| `rwx` | Read + Write + Execute (full access) |
| `rw-` | Read + Write (no execute) |
| `r-x` | Read + Execute (no write) |
| `r--` | Read only |
| `---` | No access |


#### Common Permission Patterns
| Permission | Who can do what |
| :--- | :--- |
| `-rw-------` | Only owner can read/write |
| `-rw-r--r--` | Owner read/write, everyone else read |
| `-rwxr-xr-x` | Owner full, everyone else read/execute |
| `-rwx------` | Only owner has full access |
| `drwxr-xr-x` | Directory, owner full, others can enter and list |