# Data type

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT ARE DATA TYPES?                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   DATA TYPE defines what kind of value a variable holds.        │
│                                                                  │
│   Different types of data:                                       │
│   • Numbers: 42, 3.14                                            │
│   • Text: "Hello"                                                │
│   • True/False: True, False                                      │
│   • Collections: [1,2,3], (1,2,3)                               │
│                                                                  │
│   Why data types matter:                                         │
│   • Determines what operations are allowed                       │
│   • Determines how much memory is used                           │
│   • Prevents errors (can't add text + number)                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Dynamic Typing
```
┌─────────────────────────────────────────────────────────────────┐
│                    DYNAMIC TYPING                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Python is DYNAMICALLY TYPED:                                   │
│                                                                  │
│   • You DON'T declare the type of a variable                    │
│   • Python figures out the type automatically                    │
│   • Variables can change type during execution                   │
│                                                                  │
│   STATIC TYPING (Java, C):                                       │
│   int x = 5;        // Must declare type                        │
│   x = "Hello";      // ERROR! Can't change type                 │
│                                                                  │
│   DYNAMIC TYPING (Python):                                       │
│   x = 5             # Python knows it's int                      │
│   x = "Hello"       # Now it's string - no error!               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### type()
We have a type() function to check their data types of a variable

```python
# Python determines type at runtime

x = 5
print(type(x))        # <class 'int'>

x = 3.14
print(type(x))        # <class 'float'>

x = "Hello"
print(type(x))        # <class 'str'>

x = True
print(type(x))        # <class 'bool'>

x = [1, 2, 3]
print(type(x))        # <class 'list'>

# The type() function tells you the current type
```


## All Data Types
```
┌─────────────────────────────────────────────────────────────────┐
│                 PYTHON DATA TYPES                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  NUMERIC TYPES                                                   │
│  ├── int        → Whole numbers: 42, -10, 0                     │
│  ├── float      → Decimal numbers: 3.14, -0.5, 2.0              │
│  └── complex    → Complex numbers: 3+4j, 2-1j                   │
│                                                                  │
│  BOOLEAN TYPE                                                    │
│  └── bool       → True or False                                 │
│                                                                  │
│  SEQUENCE TYPES                                                  │
│  ├── str        → Text: "Hello", 'World'                        │
│  ├── list       → Mutable sequence: [1, 2, 3]                   │
│  └── tuple      → Immutable sequence: (1, 2, 3)                 │
│                                                                  │
│  MAPPING TYPE                                                    │
│  └── dict       → Key-value pairs: {"name": "Alice"}            │
│                                                                  │
│  SET TYPES                                                       │
│  ├── set        → Unique elements: {1, 2, 3}                    │
│  └── frozenset  → Immutable set                                 │
│                                                                  │
│  NONE TYPE                                                       │
│  └── NoneType   → Absence of value: None                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Numeric Data Types
### 1. Integer (int)
```
┌─────────────────────────────────────────────────────────────────┐
│                    INTEGER (int)                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   • Whole numbers (no decimal point)                             │
│   • Positive, negative, or zero                                  │
│   • No size limit in Python!                                     │
│                                                                  │
│   Examples: 42, -10, 0, 1000000, -999                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
# Basic integers
age = 25
port = 443
negative = -100
zero = 0

# Large integers (no limit in Python!)
big_number = 99999999999999999999999999999
print(big_number)      # Works perfectly!

# Check type
print(type(age))       # <class 'int'>
```


### 2. Float (float)
```
┌─────────────────────────────────────────────────────────────────┐
│                    FLOAT (float)                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   • Numbers with decimal points                                  │
│   • Also called "floating-point numbers"                         │
│   • Can represent very large or very small numbers               │
│                                                                  │
│   Examples: 3.14, -0.5, 2.0, 1.5e-10                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
# Basic floats
pi = 3.14159
temperature = -40.5
price = 19.99
percentage = 0.75

# Integer with decimal point becomes float
value = 5.0
print(type(value))     # <class 'float'>

# Check type
print(type(pi))        # <class 'float'>
```

### 3. Complex (complex)
```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPLEX (complex)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   • Numbers with real and imaginary parts                        │
│   • Imaginary part uses 'j' (not 'i' like in math)              │
│   • Format: real + imaginary j                                   │
│                                                                  │
│   Examples: 3+4j, 2-1j, 5j, complex(3, 4)                       │
│                                                                  │
│   Note: Rarely used in cybersecurity                            │
│   More common in: signal processing, scientific computing       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
# Method 1: Direct notation
z1 = 3 + 4j
z2 = 2 - 1j
z3 = 5j           # Only imaginary part

# Method 2: Using complex() function
z4 = complex(3, 4)    # Same as 3 + 4j

print(z1)             # (3+4j)
print(type(z1))       # <class 'complex'>
```

## Boolean Data Type
```
┌─────────────────────────────────────────────────────────────────┐
│                    BOOLEAN (bool)                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   • Only two possible values: True or False                      │
│   • Used for logic and decision making                           │
│   • Case sensitive: True ✓  true ✗                              │
│                                                                  │
│   Named after mathematician George Boole                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
# Direct assignment
is_admin = True
is_blocked = False
is_connected = True

# Check type
print(type(is_admin))     # <class 'bool'>

# IMPORTANT: Case matters!
x = True      # ✓ Correct
# x = true    # ✗ Error: 'true' is not defined
# x = TRUE    # ✗ Error: 'TRUE' is not defined
```

## Sequence Data Types
### 1. String (str)
```
┌─────────────────────────────────────────────────────────────────┐
│                    STRING (str)                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   • Text data - sequence of characters                           │
│   • Enclosed in quotes: "text" or 'text' or """text"""          │
│   • IMMUTABLE - cannot be changed after creation                 │
│   • Ordered - characters have positions (index)                  │
│                                                                  │
│   Examples: "Hello", 'World', "192.168.1.1", "admin@email.com"  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
# Single quotes
name = 'Alice'

# Double quotes
message = "Hello, World!"

# Triple quotes (multi-line)
paragraph = """This is line 1.
This is line 2.
This is line 3."""

# Empty string
empty = ""

# String with numbers (still a string!)
port = "443"
print(type(port))      # <class 'str'>

# Check type
print(type(name))      # <class 'str'>
```

### 2. List (list)
```
┌─────────────────────────────────────────────────────────────────┐
│                    LIST (list)                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   • Ordered collection of items                                  │
│   • MUTABLE - can be changed after creation                      │
│   • Can contain different data types                             │
│   • Enclosed in square brackets [ ]                              │
│   • Items separated by commas                                    │
│                                                                  │
│   Examples: [1, 2, 3], ["a", "b"], [1, "hello", True]           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
# List of integers
ports = [22, 80, 443, 8080]

# List of strings
users = ["admin", "guest", "root"]

# Mixed types
mixed = [1, "hello", 3.14, True, None]

# Empty list
empty_list = []

# List from range
numbers = list(range(1, 6))    # [1, 2, 3, 4, 5]

# Nested list (list inside list)
matrix = [[1, 2], [3, 4], [5, 6]]

# Check type
print(type(ports))     # <class 'list'>
```

#### Accessing List Elements
```python
fruits = ["apple", "banana", "cherry", "date"]
#           0         1         2        3     (positive index)
#          -4        -3        -2       -1     (negative index)

# Single element
print(fruits[0])       # "apple" (first)
print(fruits[2])       # "cherry" (third)
print(fruits[-1])      # "date" (last)
print(fruits[-2])      # "cherry" (second to last)

# Slicing [start:stop:step]
print(fruits[1:3])     # ["banana", "cherry"]
print(fruits[:2])      # ["apple", "banana"]
print(fruits[2:])      # ["cherry", "date"]
print(fruits[::2])     # ["apple", "cherry"] (every 2nd)
print(fruits[::-1])    # ["date", "cherry", "banana", "apple"] (reversed)
```
#### Lists are MUTABLE
```python
# Unlike strings, lists CAN be changed!

numbers = [1, 2, 3, 4, 5]

# Change an element
numbers[0] = 100
print(numbers)         # [100, 2, 3, 4, 5]

# Change multiple elements
numbers[1:3] = [200, 300]
print(numbers)         # [100, 200, 300, 4, 5]
```

### 3. Tuple (tuple)
```
┌─────────────────────────────────────────────────────────────────┐
│                    TUPLE (tuple)                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   • Ordered collection of items (like list)                      │
│   • IMMUTABLE - cannot be changed after creation                 │
│   • Enclosed in parentheses ( )                                  │
│   • Faster than lists                                            │
│   • Used for data that shouldn't change                          │
│                                                                  │
│   Examples: (1, 2, 3), ("a", "b"), (1, "hello", True)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


```python
# Tuple of integers
coordinates = (10, 20)

# Tuple of strings
days = ("Monday", "Tuesday", "Wednesday")

# Mixed types
data = (1, "hello", 3.14, True)

# Single element tuple (needs comma!)
single = (42,)         # This is a tuple
not_tuple = (42)       # This is just an integer!

print(type(single))    # <class 'tuple'>
print(type(not_tuple)) # <class 'int'>

# Empty tuple
empty = ()

# Tuple without parentheses (tuple packing)
person = "Alice", 25, "admin"
print(type(person))    # <class 'tuple'>

# Check type
print(type(coordinates))   # <class 'tuple'>
```

#### Accessing Tuple Elements
```python
# Same as lists - use index
colors = ("red", "green", "blue", "yellow")
#          0        1       2        3

print(colors[0])       # "red"
print(colors[-1])      # "yellow"
print(colors[1:3])     # ("green", "blue")
```

#### Tuples are IMMUTABLE
```python
# Cannot change tuple after creation!

point = (10, 20)

# This will cause ERROR:
# point[0] = 100       # TypeError: 'tuple' object does not support item assignment

# To "change", create a new tuple
new_point = (100, point[1])
print(new_point)       # (100, 20)
```

# Summary
```
┌─────────────────────────────────────────────────────────────────┐
│                    MODULE 10 SUMMARY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DYNAMIC TYPING:                                                 │
│  • No need to declare types                                      │
│  • Python determines type automatically                          │
│  • Variables can change type                                     │
│                                                                  │
│  NUMERIC TYPES:                                                  │
│  • int: Whole numbers (42, -10, 0)                              │
│  • float: Decimal numbers (3.14, -0.5)                          │
│  • complex: Complex numbers (3+4j)                              │
│                                                                  │
│  BOOLEAN TYPE:                                                   │
│  • bool: True or False                                          │
│  • Used for logic and conditions                                │
│  • Truthy/Falsy values                                          │
│                                                                  │
│  SEQUENCE TYPES:                                                 │
│  • str: Text data, immutable ("Hello")                          │
│  • list: Ordered, mutable ([1, 2, 3])                           │
│  • tuple: Ordered, immutable ((1, 2, 3))                        │
│                                                                  │
│  TYPE CHECKING:                                                  │
│  • type(x) - returns the type                                   │
│  • isinstance(x, int) - check if specific type                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```