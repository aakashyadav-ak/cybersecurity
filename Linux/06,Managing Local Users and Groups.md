# User and Group Concepts
## User?
A user is an account that can log into the system.

**Every user has:**
- Username - Name to login (like "john")
- UID - User ID number (like 1001)
- Home folder - Personal folder (like /home/john)
- Shell - Program to use (like /bin/bash)

#### Types of Users

| Type | UID Range | Purpose | Example |
| :--- | :--- | :--- | :--- |
| **Root** | `0` | Super admin, full power | `root` |
| **System users** | `1-999` | Run services, no login | `apache`, `mysql` |
| **Regular users** | `1000+` | Normal people | `john`, `sarah` |


## Group?
A group is a collection of users.

Groups help manage permissions for multiple users at once.

**Example:**
- Group "developers" has users: john, sarah, mike
- All of them can access the same files

#### Every User Has
| Item                 | Description                            |
| :------------------- | :------------------------------------- |
| **Primary group**    | Main group (usually same name as user) |
| **Secondary groups** | Additional groups user belongs to      |

**Example:**
- User "john"
- Primary group: john
- Secondary groups: developers, wheel


## Important Files

| File | What it stores |
|------|----------------|
| /etc/passwd | User account information |
| /etc/shadow | Encrypted passwords |
| /etc/group | Group information |

### Understanding /etc/passwd
```
cat /etc/passwd
```

**Each line is one user:**
```
john:x:1001:1001:John Smith:/home/john:/bin/bash
```

| Part | Meaning |
|------|---------|
| john | Username |
| x | Password is in `/etc/shadow` |
| 1001 | User ID (UID) |
| 1001 | Group ID (GID) |
| John Smith | Description / Full name |
| /home/john | Home directory |
| /bin/bash | Login shell |
### Understanding /etc/group
```
cat /etc/group
```

**Each line is one group:**
```
developers:x:1010:john,sarah,mike
```


| Part | Meaning |
| :--- | :--- |
| `developers` | Group name |
| `x` | Password (usually empty) |
| `1010` | Group ID (GID) |
| `john,sarah,mike` | Members of this group |

**What groups am I in?**
```
groups
```


---

# Gain Superuser Access
## Root?
Root is the superuser - the most powerful account.

- UID is always 0
- Can do ANYTHING on the system
- Can read/write/delete any file
- Can add/remove users
- Very dangerous if misused!


#### Root Prompt vs Normal Prompt
```
[john@server ~]$              # Normal user ($ sign)
[root@server ~]#              # Root user (# sign)
```

- $ = regular user
-  # = root user


### Two Ways to Get Root Power

| Method   | Command        | What it does            |
| :------- | :------------- | :---------------------- |
| **su**   | `su -`         | Switch to root user     |
| **sudo** | `sudo command` | Run one command as root |

#### Using su (Switch User)
**Switch to root:**
```
su -
```
Enter root password. Now you ARE root.

**Switch to another user:**
```
su - <username>
```

**Exit back:**
```
exit
```

#### Using sudo 

**Run ONE command with root power:**
```
sudo cat /etc/shadow
```
Enter YOUR password (not root's).

**Why sudo is better:**
- Don't need to know root password
- Only runs one command as root
- Logs what you did
- Safer than being root all the time


### Who Can Use sudo?
Users in the wheel group can use sudo.

**Check if you can use sudo:**
```
groups
```

Look for "wheel" in the list.


**Check sudo configuration:**
```
sudo cat /etc/sudoers
```

**common commands:**
```
sudo cat /etc/shadow            # View shadow file
sudo useradd newuser            # Add user
sudo passwd john                # Change password
sudo systemctl restart sshd     # Restart service
sudo vim /etc/hosts             # Edit system file
```


### Run Shell as Root
```
sudo -i                         # Get root shell
sudo -s                         # Get root shell (keeps environment)
```