# String

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT ARE STRINGS?                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   A STRING is a sequence of characters (text data).             │
│                                                                  │
│   • Enclosed in quotes: "text" or 'text' or """text"""          │
│   • Can contain letters, numbers, symbols, spaces               │
│   • IMMUTABLE - cannot be changed after creation                 │
│   • ORDERED - each character has a position (index)             │
│                                                                  │
│   Examples:                                                      │
│   • "Hello, World!"                                              │
│   • "192.168.1.1"                                                │
│   • "admin@example.com"                                          │
│   • "Password123!"                                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## String Declaration
### Single Quotes vs Double Quotes
```python
# Both are exactly the same!
name1 = "Alice"
name2 = 'Alice'

print(name1 == name2)    # True (they are equal)
```

### Triple Quotes (Multi-line Strings)
```python
# Triple double quotes
paragraph1 = """This is line 1.
This is line 2.
This is line 3."""

# Triple single quotes
paragraph2 = '''First line.
Second line.
Third line.'''

print(paragraph1)
# Output:
# This is line 1.
# This is line 2.
# This is line 3.

# Useful for long text
sql_query = """
SELECT username, password
FROM users
WHERE role = 'admin'
"""
print(sql_query)
```


### Empty String
```python
empty = ""
also_empty = ''

print(len(empty))    # 0
print(bool(empty))   # False (empty string is falsy)

# Check if string is empty
if empty:
    print("Has content")
else:
    print("Empty string")    # This prints
```


### String with Numbers
```python
# Numbers in quotes are STRINGS, not numbers!

port_string = "443"
port_number = 443

print(type(port_string))    # <class 'str'>
print(type(port_number))    # <class 'int'>

# Cannot do math with string numbers!
# print(port_string + 1)    # ERROR! TypeError

# Must convert first
print(int(port_string) + 1)  # 444
```


## Escape Characters
```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCAPE CHARACTERS                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Escape characters start with backslash (\)                    │
│   They represent special characters in strings                   │
│                                                                  │
│   Common escape characters:                                      │
│   ┌──────────┬────────────────────────────────────────────┐     │
│   │  Code    │  Meaning                                   │     │
│   ├──────────┼────────────────────────────────────────────┤     │
│   │  \n      │  New line (go to next line)               │     │
│   │  \t      │  Tab (horizontal space)                   │     │
│   │  \\      │  Backslash itself                         │     │
│   │  \'      │  Single quote                             │     │
│   │  \"      │  Double quote                             │     │
│   │  \r      │  Carriage return                          │     │
│   │  \b      │  Backspace                                │     │
│   └──────────┴────────────────────────────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### \n - New Line
```python
# \n creates a new line
print("Line 1\nLine 2\nLine 3")
# Output:
# Line 1
# Line 2
# Line 3

# Security log example
log = "2024-01-15: Login attempt\n2024-01-15: Login failed\n2024-01-15: Account locked"
print(log)
# Output:
# 2024-01-15: Login attempt
# 2024-01-15: Login failed
# 2024-01-15: Account locked
```

### \t - Tab
```python
# \t creates a tab space
print("Name\tAge\tCity")
print("Alice\t25\tNew York")
print("Bob\t30\tBoston")
# Output:
# Name    Age     City
# Alice   25      New York
# Bob     30      Boston

# Formatted table
print("Port\tStatus\tService")
print("22\tOpen\tSSH")
print("80\tOpen\tHTTP")
print("443\tOpen\tHTTPS")
```

### \ - Backslash
```python
# To print a backslash, use \\
print("C:\\Users\\Admin\\Documents")
# Output: C:\Users\Admin\Documents

print("Path: C:\\Windows\\System32")
# Output: Path: C:\Windows\System32

# Single backslash won't work as expected
# print("C:\Users\new")    # \n becomes newline!
```

### ' and " - Quotes
```python
# Escape quotes inside string
print("He said \"Hello\"")
# Output: He said "Hello"

print('It\'s Python')
# Output: It's Python

# Mix of both
print("She said \"It\'s amazing!\"")
# Output: She said "It's amazing!"
```

### Raw Strings (Ignore Escape Characters)
```python
# Escape quotes inside string
print("He said \"Hello\"")
# Output: He said "Hello"

print('It\'s Python')
# Output: It's Python

# Mix of both
print("She said \"It\'s amazing!\"")
# Output: She said "It's amazing!"
```

# Indexing & Slicing

## String Indexing
```
┌─────────────────────────────────────────────────────────────────┐
│                    STRING INDEXING                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Each character has a position number (index)                   │
│                                                                  │
│   String:  P   y   t   h   o   n                                │
│            │   │   │   │   │   │                                │
│   Index:   0   1   2   3   4   5   (positive - left to right)   │
│           -6  -5  -4  -3  -2  -1   (negative - right to left)   │
│                                                                  │
│   Syntax: string[index]                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
text = "Python"

# Positive indexing (starts from 0)
print(text[0])      # P (first character)
print(text[1])      # y (second character)
print(text[2])      # t
print(text[5])      # n (last character)

# Negative indexing (starts from -1)
print(text[-1])     # n (last character)
print(text[-2])     # o (second to last)
print(text[-6])     # P (first character)

# Index out of range causes error
# print(text[10])   # ERROR! IndexError
```

## String Slicing

```
┌─────────────────────────────────────────────────────────────────┐
│                    STRING SLICING                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Extract a PORTION of a string                                  │
│                                                                  │
│   Syntax: string[start:stop:step]                                │
│                                                                  │
│   • start: Where to begin (included)                             │
│   • stop:  Where to end (NOT included)                           │
│   • step:  How many to skip (default 1)                          │
│                                                                  │
│   All three are optional!                                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


```python
text = "Python Programming"
#       0123456789...

# Basic slicing [start:stop]
print(text[0:6])      # Python (index 0 to 5)
print(text[7:18])     # Programming (index 7 to 17)

# Omitting start (begins from 0)
print(text[:6])       # Python (same as [0:6])

# Omitting stop (goes to end)
print(text[7:])       # Programming

# Omitting both (entire string)
print(text[:])        # Python Programming

# Negative indices in slicing
print(text[-11:])     # Programming (last 11 chars)
print(text[:-12])     # Python (all except last 12)

# Step parameter [start:stop:step]
print(text[::2])      # Pto rgamn (every 2nd character)
print(text[::3])      # Ph oa (every 3rd character)

# Reverse a string
print(text[::-1])     # gnimmargorP nohtyP
```

**Example:**
```python
text = "Cybersecurity"
#       0123456789...

# First 5 characters
print(text[:5])       # Cyber

# Last 8 characters
print(text[-8:])      # security

# Middle part
print(text[5:13])     # security

# Every other character
print(text[::2])      # Cbscrt

# Reverse
print(text[::-1])     # ytirucesebyC
```


## String Operators

### Concatenation (+)
```python
# Join strings together using +

first_name = "John"
last_name = "Doe"

# Concatenate
full_name = first_name + " " + last_name
print(full_name)    # John Doe

# Build a message
ip = "192.168.1.1"
port = "443"
url = "https://" + ip + ":" + port
print(url)          # https://192.168.1.1:443

# Multiple concatenation
line = "-" + "-" + "-" + "-" + "-"
print(line)         # -----

# Cannot concatenate string + number directly!
age = 25
# message = "Age: " + age    # ERROR! TypeError

# Must convert number to string first
message = "Age: " + str(age)
print(message)      # Age: 25
```

### Repetition (*)
```python
# Repeat a string using *

# Create a line
line = "-" * 40
print(line)    # ----------------------------------------

# Create a banner
print("=" * 50)
print("       SECURITY SCANNER")
print("=" * 50)

# Repeat text
echo = "Hello " * 3
print(echo)    # Hello Hello Hello

# Create patterns
pattern = "+-" * 20
print(pattern)    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

# Indentation
indent = "    " * 3    # 12 spaces (3 tabs worth)
print(indent + "Indented text")
```

### Membership (in, not in)
```python
# Check if substring exists in string

email = "admin@example.com"

# in - returns True if found
print("@" in email)           # True
print("admin" in email)       # True
print("example" in email)     # True
print("xyz" in email)         # False

# not in - returns True if NOT found
print("xyz" not in email)     # True
print("@" not in email)       # False

# Security example: Check for SQL injection patterns
user_input = "SELECT * FROM users"

dangerous_keywords = ["SELECT", "DROP", "DELETE", "INSERT"]

for keyword in dangerous_keywords:
    if keyword in user_input.upper():
        print(f"⚠️ Warning: '{keyword}' detected in input!")
```

### Comparison Operators
```python
# Strings can be compared

# Equality
print("hello" == "hello")     # True
print("hello" == "Hello")     # False (case sensitive!)

# Inequality
print("hello" != "world")     # True

# Alphabetical comparison (based on ASCII/Unicode values)
print("apple" < "banana")     # True (a comes before b)
print("A" < "a")              # True (uppercase before lowercase)
print("abc" < "abd")          # True

# Compare lengths
name1 = "Alice"
name2 = "Bob"
print(len(name1) > len(name2))  # True (5 > 3)
```

## String Methods
```
┌─────────────────────────────────────────────────────────────────┐
│                    STRING METHODS                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Methods are functions that belong to strings.                  │
│                                                                  │
│   Syntax: string.method()                                        │
│                                                                  │
│   Strings are IMMUTABLE, so methods return NEW strings.         │
│   The original string is NOT changed.                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Case Conversion Methods
```python
text = "Hello World"

# Convert to uppercase
print(text.upper())           # HELLO WORLD

# Convert to lowercase
print(text.lower())           # hello world

# Title case (first letter of each word)
print(text.title())           # Hello World

# Capitalize (only first letter of string)
message = "hello world"
print(message.capitalize())   # Hello world

# Swap case
print(text.swapcase())        # hELLO wORLD

# Original is unchanged!
print(text)                   # Hello World (still the same)

# To save the change:
text_upper = text.upper()
print(text_upper)             # HELLO WORLD
```

### Search Methods
```python
text = "Hello World, Hello Python"

# find() - returns index of first occurrence (-1 if not found)
print(text.find("Hello"))     # 0 (first position)
print(text.find("World"))     # 6
print(text.find("xyz"))       # -1 (not found)

# rfind() - search from right (last occurrence)
print(text.rfind("Hello"))    # 13 (second "Hello")

# index() - like find() but raises error if not found
print(text.index("World"))    # 6
# print(text.index("xyz"))    # ERROR! ValueError

# count() - count occurrences
print(text.count("Hello"))    # 2
print(text.count("o"))        # 3
print(text.count("xyz"))      # 0

# startswith() and endswith()
filename = "security_log.txt"
print(filename.startswith("security"))   # True
print(filename.endswith(".txt"))         # True
print(filename.endswith(".log"))         # False

# Check multiple options with tuple
print(filename.endswith((".txt", ".log", ".csv")))  # True
```