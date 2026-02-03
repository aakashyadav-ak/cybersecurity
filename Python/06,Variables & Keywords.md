# Variables
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT ARE VARIABLES?                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   A VARIABLE is a container that stores data in memory.         │
│                                                                  │
│   Think of it like a LABELED BOX:                                │
│                                                                  │
│   ┌─────────────┐                                                │
│   │             │                                                │
│   │     42      │  ← Value stored inside                        │
│   │             │                                                │
│   └─────────────┘                                                │
│         │                                                        │
│       "age"      ← Variable name (label on the box)             │
│                                                                  │
│   In Python:  age = 42                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


### Need
```
┌─────────────────────────────────────────────────────────────────┐
│                 WHY USE VARIABLES?                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. STORE DATA                                                  │
│      Save values to use later                                    │
│                                                                  │
│   2. REUSE VALUES                                                │
│      Use same value multiple times                               │
│                                                                  │
│   3. MAKE CODE READABLE                                          │
│      Names describe what data represents                         │
│                                                                  │
│   4. EASY TO MODIFY                                              │
│      Change value in one place                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Variable Assignment
### Basic Assignment
```python
# Syntax: variable_name = value

# Assigning different types of data
name = "Alice"              # String (text)
age = 25                    # Integer (whole number)
height = 5.8                # Float (decimal number)
is_admin = True             # Boolean (True/False)

# Print the variables
print(name)                 # Alice
print(age)                  # 25
print(height)               # 5.8
print(is_admin)             # True
```

### The Assignment Operator (=)
```
┌─────────────────────────────────────────────────────────────────┐
│              UNDERSTANDING = (ASSIGNMENT)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   In Python, = means "assign" NOT "equals"                       │
│                                                                  │
│   x = 5                                                          │
│   ↑   ↑                                                          │
│   │   └── Value (what to store)                                 │
│   └────── Variable name (where to store)                        │
│                                                                  │
│   Read as: "x is assigned the value 5"                           │
│       OR: "x gets 5"                                             │
│       OR: "store 5 in x"                                         │
│                                                                  │
│   NOT: "x equals 5" (that would be ==)                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Multiple Assignments
```python
# Method 1: Assign same value to multiple variables
x = y = z = 0
print(x)    # 0
print(y)    # 0
print(z)    # 0

# Method 2: Assign different values in one line
a, b, c = 1, 2, 3
print(a)    # 1
print(b)    # 2
print(c)    # 3

# Method 3: Swap two variables
x = 10
y = 20
print(f"Before: x={x}, y={y}")    # x=10, y=20

x, y = y, x                        # Swap!
print(f"After: x={x}, y={y}")     # x=20, y=10

# Practical example: Multiple security settings
host, port, timeout = "192.168.1.1", 443, 5
print(f"Connecting to {host}:{port} (timeout: {timeout}s)")
```

## Variable Naming Rules
```
┌─────────────────────────────────────────────────────────────────┐
│              VARIABLE NAMING RULES                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   MUST FOLLOW (or you get errors):                               │
│                                                                  │
│   ✓ Can contain letters (a-z, A-Z)                              │
│   ✓ Can contain numbers (0-9)                                   │
│   ✓ Can contain underscore (_)                                  │
│   ✓ Must START with letter or underscore                        │
│                                                                  │
│   ✗ Cannot start with a number                                  │
│   ✗ Cannot contain spaces                                       │
│   ✗ Cannot contain special characters (@, #, $, %, etc.)        │
│   ✗ Cannot be a Python keyword                                  │
│                                                                  │
│   ⚠️ Python is CASE SENSITIVE                                   │
│      age, Age, AGE are THREE different variables!               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Example:**
```python
# ✓ All these are VALID variable names

name = "Alice"
Name = "Bob"
NAME = "Charlie"
_name = "David"
_Name = "Eve"
name1 = "Frank"
name_1 = "Grace"
userName = "Henry"
user_name = "Iris"
PORT_443 = 443
__private = "secret"
myVariable = "value"
my_variable = "value"
myVariable2 = "value"
```

```python
# ✗ All these are INVALID - will cause errors!

# 1name = "error"       # Cannot start with number
# user-name = "error"   # Cannot use hyphen (-)
# user name = "error"   # Cannot have spaces
# user@name = "error"   # Cannot use special characters
# class = "error"       # Cannot use Python keywords
# for = "error"         # Cannot use Python keywords
# $price = "error"      # Cannot use $
# my.variable = "error" # Cannot use dot (.)
```

# Variable Scope (Local & Global)
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT IS SCOPE?                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   SCOPE = Where a variable can be accessed                       │
│                                                                  │
│   Two types:                                                     │
│                                                                  │
│   1. GLOBAL SCOPE                                                │
│      • Variable created OUTSIDE any function                     │
│      • Can be accessed ANYWHERE in the program                   │
│                                                                  │
│   2. LOCAL SCOPE                                                 │
│      • Variable created INSIDE a function                        │
│      • Can ONLY be accessed inside that function                 │
│      • Destroyed when function ends                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


## Global Variables
```python
# Global variable - defined outside any function
message = "Hello, World!"

def greet():
    # Can READ global variable inside function
    print(message)

def show_message():
    # Can also read here
    print(message)

# Call the functions
greet()          # Output: Hello, World!
show_message()   # Output: Hello, World!
print(message)   # Output: Hello, World!
```

## Local Variables
```python
def my_function():
    # Local variable - only exists inside this function
    secret = "I am local"
    print(secret)       # Works! Inside the function

my_function()           # Output: I am local

# Trying to access local variable outside function:
# print(secret)         # ERROR! NameError: name 'secret' is not defined
```