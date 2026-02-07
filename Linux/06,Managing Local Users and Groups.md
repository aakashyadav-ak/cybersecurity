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
