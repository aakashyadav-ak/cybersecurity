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