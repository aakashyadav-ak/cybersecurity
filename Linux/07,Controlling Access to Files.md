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

