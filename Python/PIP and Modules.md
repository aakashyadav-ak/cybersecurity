# Modules
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT IS A MODULE?                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   A MODULE is a Python file (.py) containing code that can      │
│   be reused in other programs.                                   │
│                                                                  │
│   Think of it like a TOOLBOX:                                    │
│   • Instead of making tools every time                           │
│   • You use ready-made tools from a toolbox                      │
│                                                                  │
│   Module = Collection of functions, classes, variables           │
│                                                                  │
│   Example:                                                       │
│   • math module → Mathematical functions                         │
│   • random module → Random number generation                     │
│   • os module → Operating system functions                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Uses 
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHY USE MODULES?                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ✓ CODE REUSABILITY                                            │
│     Write once, use many times                                   │
│                                                                  │
│   ✓ ORGANIZATION                                                │
│     Keep related code together                                   │
│                                                                  │
│   ✓ AVOID REPETITION                                            │
│     Don't reinvent the wheel                                     │
│                                                                  │
│   ✓ EASIER MAINTENANCE                                          │
│     Fix in one place, works everywhere                           │
│                                                                  │
│   ✓ COLLABORATION                                               │
│     Share code with others easily                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Types of Modules
```
┌─────────────────────────────────────────────────────────────────┐
│                    TYPES OF MODULES                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. BUILT-IN MODULES                                             │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ • Come pre-installed with Python                        │ │
│     │ • No installation needed                                │ │
│     │ • Just import and use                                   │ │
│     │ • Examples: math, random, os, sys, datetime             │ │
│     └─────────────────────────────────────────────────────────┘ │
│                                                                  │
│  2. EXTERNAL MODULES (Third-Party)                               │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ • Created by Python community                           │ │
│     │ • Need to install using pip                             │ │
│     │ • Downloaded from PyPI (Python Package Index)           │ │
│     │ • Examples: requests, numpy, pandas, scapy              │ │
│     └─────────────────────────────────────────────────────────┘ │
│                                                                  │
│  3. USER-DEFINED MODULES                                         │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ • Created by you                                        │ │
│     │ • Your own .py files                                    │ │
│     │ • Organize your project code                            │ │
│     └─────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 1. Built-in Modules
```python
# Step 1: Import the module
import math

# Step 2: Use functions from the module
result = math.sqrt(16)
print(result)    # 4.0
```

**Common Built In Modules**
```python
import math

# Square root
print(math.sqrt(16))        # 4.0
print(math.sqrt(25))        # 5.0

# Power
print(math.pow(2, 3))       # 8.0 (2^3)
print(math.pow(10, 2))      # 100.0

# Constants
print(math.pi)              # 3.141592653589793
print(math.e)               # 2.718281828459045

# Rounding
print(math.floor(3.7))      # 3 (round down)
print(math.ceil(3.2))       # 4 (round up)

# Absolute value
print(math.fabs(-5))        # 5.0

# Factorial
print(math.factorial(5))    # 120 (5! = 5×4×3×2×1)
```

```python
# Method 1: import math
import math
print(math.sqrt(16))   # Need prefix

# Method 2: import math as m using alias
import math as m
print(m.sqrt(16))      # Shorter prefix

# Method 3: from math import sqrt
from math import sqrt
print(sqrt(16))        # No prefix needed

# Method 4: from math import *
from math import *
print(sqrt(16))        # No prefix, but risky!
```

## 2. External Modules

  **PyPI - Python Package Index**
```
┌─────────────────────────────────────────────────────────────────┐
│                    PyPI - Python Package Index                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Website: https://pypi.org                                      │
│                                                                  │
│   • Repository of Python packages                                │
│   • Over 400,000+ packages available                             │
│   • Anyone can upload packages                                   │
│   • Free to use                                                  │
│                                                                  │
│   Popular packages:                                              │
│   • requests - HTTP library                                      │
│   • numpy - Numerical computing                                  │
│   • pandas - Data analysis                                       │
│   • flask - Web framework                                        │
│   • scapy - Network packets                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

# PIP - Python Package Manager
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT IS PIP?                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   PIP = "Pip Installs Packages"                                  │
│                                                                  │
│   • Tool to install external packages                            │
│   • Downloads from PyPI automatically                            │
│   • Manages package versions                                     │
│   • Handles dependencies                                         │
│   • Comes pre-installed with Python 3.4+                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Installing Packages using PIP
```python
# Basic installation
pip install package_name

# Examples:
pip install requests
pip install numpy
pip install pandas
```

**Common pip commands**
```python
# 1. INSTALL a package
pip install requests

# 2. INSTALL specific version
pip install requests==2.28.0

# 3. UPGRADE a package
pip install --upgrade requests

# 4. UNINSTALL a package
pip uninstall requests

# 5. LIST installed packages
pip list

# 6. SHOW package information
pip show requests

# 7. SEARCH for packages (may not work in newer pip)
pip search requests

# 8. FREEZE - save installed packages to file
pip freeze > requirements.txt

# 9. INSTALL from requirements file
pip install -r requirements.txt
```

## Example: Using Built-in math Module
```python
# calculator.py
import math

print("=== Math Calculator ===")
print()

# Square root
number = 144
print(f"Square root of {number}: {math.sqrt(number)}")

# Power
base = 2
exponent = 10
print(f"{base} to the power of {exponent}: {math.pow(base, exponent)}")

# Circle area
radius = 5
area = math.pi * radius ** 2
print(f"Area of circle with radius {radius}: {area:.2f}")

# Floor and ceiling
value = 7.6
print(f"Floor of {value}: {math.floor(value)}")
print(f"Ceiling of {value}: {math.ceil(value)}")
```

# Security-Related Modules
```
┌─────────────────────────────────────────────────────────────────┐
│             MODULES FOR CYBERSECURITY                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  BUILT-IN:                                                       │
│  ├── hashlib    → Hashing (MD5, SHA256, etc.)                   │
│  ├── secrets    → Secure random numbers                         │
│  ├── socket     → Network connections                           │
│  └── ssl        → SSL/TLS encryption                            │
│                                                                  │
│  EXTERNAL (pip install):                                        │
│  ├── requests   → HTTP requests                                 │
│  ├── scapy      → Packet manipulation                           │
│  ├── paramiko   → SSH connections                               │
│  ├── pycryptodome → Encryption/Decryption                      │
│  ├── python-nmap → Nmap port scanning                          │
│  └── beautifulsoup4 → Web scraping                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Example: hashlib (Built-in)
```python
import hashlib

# Hash a password (for demonstration)
password = "MySecretPassword123"

# Create MD5 hash
md5_hash = hashlib.md5(password.encode()).hexdigest()
print(f"MD5: {md5_hash}")

# Create SHA256 hash (more secure)
sha256_hash = hashlib.sha256(password.encode()).hexdigest()
print(f"SHA256: {sha256_hash}")
```

**Output**
```
MD5: 5f4dcc3b5aa765d61d8327deb882cf99
SHA256: a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
```