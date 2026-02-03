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