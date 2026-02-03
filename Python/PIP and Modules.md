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

## 1.Built-in Modules
```python
# Step 1: Import the module
import math

# Step 2: Use functions from the module
result = math.sqrt(16)
print(result)    # 4.0
```