# Tuple
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT IS A TUPLE?                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   A TUPLE is an ordered, IMMUTABLE collection of items.         │
│                                                                  │
│   Think of it like a READ-ONLY list:                            │
│   • Once created, it CANNOT be changed                           │
│   • Items cannot be added, removed, or modified                  │
│                                                                  │
│   Syntax: Uses parentheses ( )                                   │
│                                                                  │
│   List:   [1, 2, 3]    ← Mutable (can change)                   │
│   Tuple:  (1, 2, 3)    ← Immutable (cannot change)              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Tuple Definition
### Creating Tuples

**Tuples are created using parentheses ( )**
```python
# Tuples are created using parentheses ( )

# Tuple of integers
ports = (22, 80, 443)

# Tuple of strings
protocols = ("HTTP", "HTTPS", "FTP", "SSH")

# Tuple of mixed types
data = (1, "hello", 3.14, True, None)

# Empty tuple
empty = ()

# Check type
print(type(ports))    # <class 'tuple'>
```

### Single Element Tuple 
```python
# Single element tuple MUST have a comma!

# WRONG - This is just an integer in parentheses!
not_tuple = (42)
print(type(not_tuple))    # <class 'int'>

# CORRECT - Add a comma
single_tuple = (42,)
print(type(single_tuple)) # <class 'tuple'>

# Also correct - comma without parentheses
another = 42,
print(type(another))      # <class 'tuple'>
```

### Tuple Without Parentheses (Tuple Packing)
```python
# Parentheses are optional!

# With parentheses
point1 = (10, 20)

# Without parentheses (same thing!)
point2 = 10, 20

print(type(point1))    # <class 'tuple'>
print(type(point2))    # <class 'tuple'>
print(point1 == point2)  # True

# Multiple values
server_info = "192.168.1.1", 443, "HTTPS"
print(server_info)        # ('192.168.1.1', 443, 'HTTPS')
print(type(server_info))  # <class 'tuple'>
```

#### Different Ways to Create Tuples
```python
# Method 1: Direct creation with ( )
colors = ("red", "green", "blue")

# Method 2: tuple() constructor
numbers = tuple([1, 2, 3, 4, 5])    # From list
print(numbers)    # (1, 2, 3, 4, 5)

# Method 3: From string
chars = tuple("Python")
print(chars)      # ('P', 'y', 't', 'h', 'o', 'n')

# Method 4: From range
nums = tuple(range(1, 6))
print(nums)       # (1, 2, 3, 4, 5)

# Method 5: Without parentheses
data = 1, 2, 3
print(data)       # (1, 2, 3)
```

## Characteristics of Tuples
```
┌─────────────────────────────────────────────────────────────────┐
│              CHARACTERISTICS OF TUPLES                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. ORDERED                                                     │
│      • Items have a defined order                                │
│      • Order is maintained                                       │
│      • Items can be accessed by index                            │
│                                                                  │
│   2. IMMUTABLE (Cannot change!)                                  │
│      • Cannot add items                                          │
│      • Cannot remove items                                       │
│      • Cannot modify items                                       │
│                                                                  │
│   3. ALLOWS DUPLICATES                                           │
│      • Same value can appear multiple times                      │
│                                                                  │
│   4. HETEROGENEOUS                                               │
│      • Can contain different data types                          │
│                                                                  │
│   5. FASTER THAN LISTS                                           │
│      • Less memory usage                                         │
│      • Quicker access                                            │
│                                                                  │
│   6. CAN BE DICTIONARY KEY                                       │
│      • Unlike lists, tuples can be dict keys                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Example:**
```python
# 1. ORDERED - Items have positions
colors = ("red", "green", "blue")
print(colors[0])    # red (always first)
print(colors[1])    # green (always second)

# 2. IMMUTABLE - Cannot be changed!
point = (10, 20)
# point[0] = 100    # ERROR! TypeError: 'tuple' object does not support item assignment

# 3. ALLOWS DUPLICATES
numbers = (1, 2, 2, 3, 3, 3)
print(numbers)      # (1, 2, 2, 3, 3, 3)

# 4. HETEROGENEOUS - Mixed types
mixed = (42, "hello", 3.14, True, None)
print(mixed)

# 5. FASTER THAN LISTS
# (You won't notice with small data, but matters with large data)

# 6. CAN BE DICTIONARY KEY
locations = {
    (40.7128, -74.0060): "New York",
    (51.5074, -0.1278): "London"
}
print(locations[(40.7128, -74.0060)])    # New York

# Lists CANNOT be dictionary keys
# locations = {[1, 2]: "test"}    # ERROR! TypeError: unhashable type: 'list'
```


## Accessing Tuple Items

### Indexing
```python
# Same as lists - use index

protocols = ("FTP", "SSH", "HTTP", "HTTPS", "DNS")
#              0      1       2       3       4     (positive)
#             -5     -4      -3      -2      -1     (negative)

# Positive indexing
print(protocols[0])     # FTP (first)
print(protocols[2])     # HTTP (third)
print(protocols[4])     # DNS (last)

# Negative indexing
print(protocols[-1])    # DNS (last)
print(protocols[-2])    # HTTPS (second to last)
print(protocols[-5])    # FTP (first)

# Index out of range
# print(protocols[10])  # ERROR! IndexError
```

### Slicing
```python
# Same slicing rules as lists

ports = (21, 22, 23, 80, 443, 3306, 8080)
#         0   1   2   3   4    5     6

# Basic slicing [start:stop]
print(ports[1:4])       # (22, 23, 80)
print(ports[0:3])       # (21, 22, 23)

# Omitting start (from beginning)
print(ports[:3])        # (21, 22, 23)

# Omitting stop (to end)
print(ports[4:])        # (443, 3306, 8080)

# Omitting both (entire tuple)
print(ports[:])         # (21, 22, 23, 80, 443, 3306, 8080)

# Negative slicing
print(ports[-3:])       # (443, 3306, 8080) (last 3)
print(ports[:-2])       # (21, 22, 23, 80, 443)

# Step parameter
print(ports[::2])       # (21, 23, 443, 8080) (every 2nd)

# Reverse
print(ports[::-1])      # (8080, 3306, 443, 80, 23, 22, 21)
```


## Tuple Unpacking
```
┌─────────────────────────────────────────────────────────────────┐
│                    TUPLE UNPACKING                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Assign tuple values to multiple variables at once.            │
│                                                                  │
│   (a, b, c) = (1, 2, 3)                                         │
│                                                                  │
│   Now: a=1, b=2, c=3                                            │
│                                                                  │
│   Very useful for:                                               │
│   • Function returns                                             │
│   • Loop iterations                                              │
│   • Swapping variables                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


```python
# Basic unpacking
coordinates = (10, 20, 30)
x, y, z = coordinates

print(x)    # 10
print(y)    # 20
print(z)    # 30

# Server info unpacking
server = ("192.168.1.1", 443, "https")
ip, port, protocol = server

print(f"Connecting to {protocol}://{ip}:{port}")
# Output: Connecting to https://192.168.1.1:443

# Unpacking in one line
a, b, c = 1, 2, 3
print(a, b, c)    # 1 2 3
```

## Tuple Methods
```
┌─────────────────────────────────────────────────────────────────┐
│                    TUPLE METHODS                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Tuples have ONLY 2 methods (because they're immutable):       │
│                                                                  │
│   1. count(value)  - Count occurrences of a value               │
│   2. index(value)  - Find position of a value                   │
│                                                                  │
│   That's it! No append, remove, sort, etc.                      │
│   (Those would change the tuple, which is not allowed)          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### count() Method
```python
# count(value) - Returns number of times value appears

# Simple example
numbers = (1, 2, 2, 3, 3, 3, 4, 4, 4, 4)

print(numbers.count(1))    # 1
print(numbers.count(2))    # 2
print(numbers.count(3))    # 3
print(numbers.count(4))    # 4
print(numbers.count(5))    # 0 (not found)

# String example
protocols = ("HTTP", "HTTPS", "HTTP", "FTP", "HTTP")
print(protocols.count("HTTP"))     # 3
print(protocols.count("HTTPS"))    # 1
print(protocols.count("SSH"))      # 0
```

#### index() Method
```python
# index(value) - Returns index of FIRST occurrence

protocols = ("FTP", "SSH", "HTTP", "HTTPS", "HTTP")

print(protocols.index("SSH"))      # 1
print(protocols.index("HTTP"))     # 2 (first occurrence)
print(protocols.index("HTTPS"))    # 3

# Value not found - ERROR!
# print(protocols.index("DNS"))    # ValueError!

# Safe way - check first
if "DNS" in protocols:
    print(protocols.index("DNS"))
else:
    print("DNS not found")
```

## Tuple Operations
### Concatenation (+)
```python
# Combine tuples using +

tuple1 = (1, 2, 3)
tuple2 = (4, 5, 6)

combined = tuple1 + tuple2
print(combined)    # (1, 2, 3, 4, 5, 6)

# Original tuples unchanged (immutable!)
print(tuple1)      # (1, 2, 3)
print(tuple2)      # (4, 5, 6)

# Security example: Combine port lists
web_ports = (80, 443, 8080)
mail_ports = (25, 110, 143)
db_ports = (3306, 5432, 27017)

all_ports = web_ports + mail_ports + db_ports
print(f"All ports to scan: {all_ports}")
```


### Repetition (*)
```python
# Repeat tuple using *

pattern = (1, 2)
repeated = pattern * 4
print(repeated)    # (1, 2, 1, 2, 1, 2, 1, 2)

# Create tuple of same values
zeros = (0,) * 5
print(zeros)       # (0, 0, 0, 0, 0)

# Note: Need comma for single element!
wrong = (0) * 5    # This is just 0 * 5 = 0 (integer!)
print(wrong)       # 0
```

### Length, Min, Max, Sum
```python
ports = (22, 80, 443, 3306, 8080)

# Length
print(len(ports))      # 5

# Minimum
print(min(ports))      # 22

# Maximum
print(max(ports))      # 8080

# Sum
print(sum(ports))      # 11931

# Average
average = sum(ports) / len(ports)
print(f"Average: {average}")    # 2386.2
```

#### Tuple vs List Comparison
```
┌─────────────────────────────────────────────────────────────────┐
│                    TUPLE vs LIST                                 │
├───────────────────────────┬─────────────────────────────────────┤
│          TUPLE            │              LIST                    │
├───────────────────────────┼─────────────────────────────────────┤
│ Syntax: (1, 2, 3)         │ Syntax: [1, 2, 3]                   │
├───────────────────────────┼─────────────────────────────────────┤
│ IMMUTABLE (cannot change) │ MUTABLE (can change)                │
├───────────────────────────┼─────────────────────────────────────┤
│ Faster                    │ Slower                              │
├───────────────────────────┼─────────────────────────────────────┤
│ Less memory               │ More memory                         │
├───────────────────────────┼─────────────────────────────────────┤
│ Can be dictionary key     │ Cannot be dictionary key            │
├───────────────────────────┼─────────────────────────────────────┤
│ 2 methods only            │ Many methods                        │
│ (count, index)            │ (append, remove, sort, etc.)        │
├───────────────────────────┼─────────────────────────────────────┤
│ Use for fixed data        │ Use for data that changes           │
├───────────────────────────┼─────────────────────────────────────┤
│ Examples:                 │ Examples:                           │
│ • Coordinates (x, y)      │ • Shopping list                     │
│ • RGB colors              │ • User list                         │
│ • Database record         │ • Scan results                      │
│ • Configuration           │ • Log entries                       │
└───────────────────────────┴─────────────────────────────────────┘
```


# Summary
```
┌─────────────────────────────────────────────────────────────────┐
│                    MODULE 13 SUMMARY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TUPLE DEFINITION:                                               │
│  • Created with parentheses: (1, 2, 3)                          │
│  • Single element needs comma: (42,)                            │
│  • Can omit parentheses: a, b, c = 1, 2, 3                      │
│                                                                  │
│  CHARACTERISTICS:                                                │
│  • Ordered (has index)                                          │
│  • IMMUTABLE (cannot change!)                                   │
│  • Allows duplicates                                            │
│  • Faster than lists                                            │
│  • Can be dictionary keys                                       │
│                                                                  │
│  ACCESSING ITEMS:                                                │
│  • Indexing: tuple[0], tuple[-1]                                │
│  • Slicing: tuple[1:4], tuple[::-1]                             │
│  • Unpacking: a, b, c = my_tuple                                │
│                                                                  │
│  METHODS (Only 2!):                                              │
│  • count(value) - count occurrences                             │
│  • index(value) - find position                                 │
│                                                                  │
│  OPERATIONS:                                                     │
│  • + (concatenation)                                            │
│  • * (repetition)                                               │
│  • in, not in (membership)                                      │
│  • len(), min(), max(), sum()                                   │
│                                                                  │
│  WHEN TO USE:                                                    │
│  • Fixed data that shouldn't change                             │
│  • Coordinates, configurations, constants                       │
│  • Dictionary keys                                              │
│  • Faster/safer than lists for static data                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```
