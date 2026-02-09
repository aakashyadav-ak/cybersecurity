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
| Permission   | Who can do what                                  |
| :----------- | :----------------------------------------------- |
| `-rw-------` | Only owner can read/write                        |
| `-rw-r--r--` | Owner read/write, everyone else read             |
| `-rwxr-xr-x` | Owner full, everyone else read/execute           |
| `-rwx------` | Only owner has full access                       |
| `drwxr-xr-x` | Directory, owner full, others can enter and list |

#### Numeric (Octal) Permissions
**Each permission has a number:**

| Permission | Number |
| :--- | :--- |
| **Read** (`r`) | `4` |
| **Write** (`w`) | `2` |
| **Execute** (`x`) | `1` |
| **None** (`-`) | `0` |

**Add them together:**
```
| Permissions | Calculation | Number |
| :--- | :--- | :--- |
| `rwx` | 4 + 2 + 1 | **7** |
| `rw-` | 4 + 2 + 0 | **6** |
| `r-x` | 4 + 0 + 1 | **5** |
| `r--` | 4 + 0 + 0 | **4** |
| `-wx` | 0 + 2 + 1 | **3** |
| `-w-` | 0 + 2 + 0 | **2** |
| `--x` | 0 + 0 + 1 | **1** |
| `---` | 0 + 0 + 0 | **0** |
```

#### Three-Digit Permission Numbers
```
-rw-r--r--  =  644
 │   │  │
 │   │  └── Others: r-- = 4
 │   └───── Group:  r-- = 4
 └───────── Owner:  rw- = 6
```

| Number  | Permission  | Use case                             |
| :------ | :---------- | :----------------------------------- |
| **777** | `rwxrwxrwx` | ⚠️ Everyone full access (dangerous!) |
| **755** | `rwxr-xr-x` | Executables, directories             |
| **700** | `rwx------` | Private directories                  |
| **644** | `rw-r--r--` | Normal files                         |
| **600** | `rw-------` | Private files                        |
| **400** | `r--------` | Read-only private files              |

### Check File Permissions
```
ls -l <filename>
```

#### Check directory permissions:
```
ls -ld directoryname
```

#### Check all files including hidden:
```
ls -la
```


___

# Manage File System Permissions from the Command Line

## chmod - Change Permissions

**Two ways to use chmod:**
- Symbolic method (letters)
- Numeric method (numbers)


### Symbolic Method

**Format:**
```
chmod WHO+/-PERMISSION filename
```

**example:**
```
chmod u+x script.sh
```

#### WHO:
| Letter | Meaning        |
| :----- | :------------- |
| `u`    | Owner (user)   |
| `g`    | Group          |
| `o`    | Others         |
| `a`    | All (everyone) |

#### Operators:
| Symbol | Meaning              |
| :----- | :------------------- |
| `+`    | Add permission       |
| `-`    | Remove permission    |
| `=`    | Set exact permission |

### Symbolic Examples

**Add execute for owner:**
```
chmod u+x script.sh
```


**Remove write for others:**
```
chmod o-w file.txt
```


### Numeric Method

**Format:**
```
chmod NUMBER filename
```

**Examples:**

```bash
chmod 755 script.sh         # rwxr-xr-x
chmod 644 file.txt          # rw-r--r--
chmod 600 secret.txt        # rw-------
chmod 700 private_dir       # rwx------
chmod 777 open_file         # rwxrwxrwx (dangerous!)
```


## chmod for Directories

**Same commands work:**
```
chmod 755 mydir             # Owner full, others can enter/list
chmod 700 private           # Only owner can access
```


## chown - Change Owner

**Change owner:**
```
sudo chown newowner file.txt
```

**Change owner and group:**
```
sudo chown newowner:newgroup file.txt
```

**Change group only:**
```
sudo chown :newgroup file.txt
```


## chgrp - Change Group

**Change group only:**
```
sudo chgrp developers file.txt
```


___

# Manage Default Permissions and File Access
## umask - Default Permission Mask
When you create new files, what permissions do they get?

umask controls this!


#### Check Current umask
```
umask
```

**output:**
```
0022
```

### How umask Works

**Default permissions:**
- Files: 666 (no execute by default)
- Directories: 777

**umask subtracts from defaults:**
```
Files:       666 - 022 = 644 (rw-r--r--)
Directories: 777 - 022 = 755 (rwxr-xr-x)
```

## Set umask
#### Temporary (current session):
```
umask 077
```

#### Permanent (add to ~/.bashrc):
```
echo "umask 077" >> ~/.bashrc
```


## Special Permissions
**Three Special Permissions:**

| Permission     | Number | On Files          | On Directories              |
| :------------- | :----- | :---------------- | :-------------------------- |
| **SUID**       | `4`    | Run as file owner | -                           |
| **SGID**       | `2`    | Run as file group | New files inherit group     |
| **Sticky Bit** | `1`    | -                 | Only owner can delete files |


### SUID (Set User ID)
When you run the file, it runs as the owner (not you).

**Example:** /usr/bin/passwd

```
ls -l /usr/bin/passwd
-rwsr-xr-x. 1 root root 27856 Jan 1 10:00 /usr/bin/passwd
```
See the s instead of x? That's SUID.

Regular users can run passwd to change their password, and it runs as root!

#### Set SUID:
```
chmod u+s file
chmod 4755 file
```
Tip: SUID files are gold for privilege escalation!

### SGID (Set Group ID)
On files: Runs as the file's group.

On directories: New files inherit the directory's group.

**Example:**
```
ls -l
drwxrwsr-x. 2 john developers 4096 Jan 1 10:00 shared
```
See the s in group section? That's SGID.

#### Set SGID:
```
chmod g+s directory
chmod 2755 directory
```

### Sticky Bit
Only file owner can delete their files (even if others have write permission).

Used on shared directories like /tmp.
```
ls -ld /tmp
drwxrwxrwt. 10 root root 4096 Jan 1 10:00 /tmp
```
See the t at the end? That's sticky bit.

#### Set sticky bit:
```
chmod +t directory
chmod 1777 directory
```