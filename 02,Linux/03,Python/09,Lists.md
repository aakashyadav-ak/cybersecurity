# List 
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT IS A LIST?                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   A LIST is an ordered collection of items.                      │
│                                                                  │
│   Think of it like a shopping list or a to-do list:             │
│                                                                  │
│   ┌─────────────────────────────┐                               │
│   │  Shopping List:             │                               │
│   │  1. Apples                  │                               │
│   │  2. Bread                   │                               │
│   │  3. Milk                    │                               │
│   │  4. Eggs                    │                               │
│   └─────────────────────────────┘                               │
│                                                                  │
│   In Python: shopping = ["Apples", "Bread", "Milk", "Eggs"]     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Creating Lists

**Lists are created using square brackets [ ]**
```python
# Lists are created using square brackets [ ]

# List of integers
ports = [22, 80, 443, 8080]

# List of strings
users = ["admin", "guest", "root"]

# List of mixed types
mixed = [1, "hello", 3.14, True, None]

# Empty list
empty_list = []

# List with one item
single = [42]

# Check type
print(type(ports))    # <class 'list'>
```

**Different Ways to Create Lists**
```python
# Method 1: Direct creation with [ ]
fruits = ["apple", "banana", "cherry"]

# Method 2: Using list() constructor
numbers = list((1, 2, 3, 4, 5))    # From tuple
print(numbers)    # [1, 2, 3, 4, 5]

# Method 3: From range
numbers = list(range(1, 6))
print(numbers)    # [1, 2, 3, 4, 5]

# Method 4: From string (each character becomes an item)
chars = list("Python")
print(chars)    # ['P', 'y', 't', 'h', 'o', 'n']

# Method 5: List comprehension (we'll learn this later)
squares = [x**2 for x in range(1, 6)]
print(squares)    # [1, 4, 9, 16, 25]
```

## Characteristics of Lists
```
┌─────────────────────────────────────────────────────────────────┐
│                 CHARACTERISTICS OF LISTS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. ORDERED                                                     │
│      • Items have a defined order                                │
│      • Order is maintained                                       │
│      • Items can be accessed by index                            │
│                                                                  │
│   2. MUTABLE (Changeable)                                        │
│      • Can add, remove, modify items                             │
│      • Unlike strings and tuples                                 │
│                                                                  │
│   3. ALLOWS DUPLICATES                                           │
│      • Same value can appear multiple times                      │
│                                                                  │
│   4. HETEROGENEOUS                                               │
│      • Can contain different data types                          │
│      • [1, "hello", True, 3.14]                                 │
│                                                                  │
│   5. DYNAMIC SIZE                                                │
│      • Can grow or shrink as needed                              │
│      • No fixed size                                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Example:**
```python
# 1. ORDERED - Items have positions
fruits = ["apple", "banana", "cherry"]
print(fruits[0])    # apple (always first)
print(fruits[1])    # banana (always second)

# 2. MUTABLE - Can be changed
fruits[0] = "mango"
print(fruits)       # ['mango', 'banana', 'cherry']

# 3. ALLOWS DUPLICATES
numbers = [1, 2, 2, 3, 3, 3]
print(numbers)      # [1, 2, 2, 3, 3, 3] (duplicates allowed)

# 4. HETEROGENEOUS - Mixed types
mixed = [42, "hello", 3.14, True, None, [1, 2, 3]]
print(mixed)        # All different types in one list

# 5. DYNAMIC SIZE - Can grow/shrink
data = [1, 2, 3]
print(len(data))    # 3

data.append(4)
print(len(data))    # 4

data.pop()
print(len(data))    # 3
```

# Indexing & Slicing

## List Indexing
```
┌─────────────────────────────────────────────────────────────────┐
│                    LIST INDEXING                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Each item has a position (index)                               │
│                                                                  │
│   List:    ["SSH", "HTTP", "HTTPS", "FTP", "DNS"]               │
│              │       │       │       │      │                    │
│   Index:     0       1       2       3      4    (positive)      │
│             -5      -4      -3      -2     -1    (negative)      │
│                                                                  │
│   Syntax: list[index]                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
services = ["SSH", "HTTP", "HTTPS", "FTP", "DNS"]

# Positive indexing (left to right, starts at 0)
print(services[0])      # SSH (first item)
print(services[1])      # HTTP (second item)
print(services[4])      # DNS (fifth item)

# Negative indexing (right to left, starts at -1)
print(services[-1])     # DNS (last item)
print(services[-2])     # FTP (second to last)
print(services[-5])     # SSH (first item)

# Index out of range causes error
# print(services[10])   # ERROR! IndexError

# Check list length first
if len(services) > 5:
    print(services[5])
else:
    print("Index 5 doesn't exist")
```

## LIST SLICING 
```
┌─────────────────────────────────────────────────────────────────┐
│                    LIST SLICING                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Extract a portion of the list                                  │
│                                                                  │
│   Syntax: list[start:stop:step]                                  │
│                                                                  │
│   • start: Where to begin (included)                             │
│   • stop:  Where to end (NOT included)                           │
│   • step:  How many to skip                                      │
│                                                                  │
│   All three are optional!                                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```python
ports = [21, 22, 23, 80, 443, 3306, 8080]
#        0   1   2   3   4    5     6

# Basic slicing [start:stop]
print(ports[1:4])       # [22, 23, 80] (index 1, 2, 3)
print(ports[0:3])       # [21, 22, 23] (index 0, 1, 2)

# Omitting start (begins from 0)
print(ports[:3])        # [21, 22, 23]

# Omitting stop (goes to end)
print(ports[4:])        # [443, 3306, 8080]

# Omitting both (entire list copy)
print(ports[:])         # [21, 22, 23, 80, 443, 3306, 8080]

# Negative indices in slicing
print(ports[-3:])       # [443, 3306, 8080] (last 3)
print(ports[:-2])       # [21, 22, 23, 80, 443] (all except last 2)

# Step parameter [start:stop:step]
print(ports[::2])       # [21, 23, 443, 8080] (every 2nd item)
print(ports[1::2])      # [22, 80, 3306] (every 2nd, starting from index 1)

# Reverse a list
print(ports[::-1])      # [8080, 3306, 443, 80, 23, 22, 21]
```

## Changing List Items
### Modify Single Item
```python
# Lists are MUTABLE - can be changed!

ports = [22, 80, 443]
print(f"Before: {ports}")    # [22, 80, 443]

# Change item by index
ports[1] = 8080
print(f"After: {ports}")     # [22, 8080, 443]

# Change last item
ports[-1] = 3306
print(f"After: {ports}")     # [22, 8080, 3306]
```

### Modify Multiple Items (Slice Assignment)
```python
services = ["SSH", "HTTP", "HTTPS", "FTP", "DNS"]
print(f"Before: {services}")

# Replace a range of items
services[1:3] = ["SMTP", "IMAP"]
print(f"After: {services}")    # ['SSH', 'SMTP', 'IMAP', 'FTP', 'DNS']

# Replace with different number of items
numbers = [1, 2, 3, 4, 5]
numbers[1:4] = [20, 30]        # Replace 3 items with 2 items
print(numbers)                  # [1, 20, 30, 5]

# Insert items without removing (empty slice)
letters = ['a', 'b', 'e', 'f']
letters[2:2] = ['c', 'd']      # Insert at index 2
print(letters)                  # ['a', 'b', 'c', 'd', 'e', 'f']

# Remove items using slice
data = [1, 2, 3, 4, 5]
data[1:4] = []                  # Remove items at index 1, 2, 3
print(data)                     # [1, 5]
```

# List Methods

## Adding Items

#### append() - Add to End
```python
# append(item) - Adds ONE item to the END of the list

ports = [22, 80]
print(f"Before: {ports}")      # [22, 80]

ports.append(443)
print(f"After: {ports}")       # [22, 80, 443]

ports.append(8080)
print(f"After: {ports}")       # [22, 80, 443, 8080]

# Append different types
mixed = [1, 2, 3]
mixed.append("hello")
mixed.append(True)
print(mixed)                   # [1, 2, 3, 'hello', True]

# Append a list (adds as single item - nested list!)
list1 = [1, 2, 3]
list1.append([4, 5])
print(list1)                   # [1, 2, 3, [4, 5]] - Nested!
```

#### extend() - Add Multiple Items
```python
# extend(iterable) - Adds MULTIPLE items to the END

ports = [22, 80]
print(f"Before: {ports}")      # [22, 80]

# Extend with another list
ports.extend([443, 8080])
print(f"After: {ports}")       # [22, 80, 443, 8080]

# Extend with any iterable
ports.extend((3306, 5432))     # Tuple
print(f"After: {ports}")       # [22, 80, 443, 8080, 3306, 5432]

# Difference between append and extend
list1 = [1, 2, 3]
list2 = [1, 2, 3]

list1.append([4, 5])           # Adds as ONE item
list2.extend([4, 5])           # Adds as MULTIPLE items

print(f"append: {list1}")      # [1, 2, 3, [4, 5]]
print(f"extend: {list2}")      # [1, 2, 3, 4, 5]
```

#### insert() - Add at Specific Position
```python
# insert(index, item) - Adds item at specific position

ports = [22, 443, 8080]
print(f"Before: {ports}")      # [22, 443, 8080]

# Insert at index 1
ports.insert(1, 80)
print(f"After: {ports}")       # [22, 80, 443, 8080]

# Insert at beginning
ports.insert(0, 21)
print(f"After: {ports}")       # [21, 22, 80, 443, 8080]

# Insert at end (same as append)
ports.insert(len(ports), 3306)
print(f"After: {ports}")       # [21, 22, 80, 443, 8080, 3306]

# Insert with negative index
numbers = [1, 2, 3, 5]
numbers.insert(-1, 4)          # Insert before last item
print(numbers)                 # [1, 2, 3, 4, 5]
```

##### Comparison: append vs extend vs insert
```
┌─────────────────────────────────────────────────────────────────┐
│           append vs extend vs insert                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   METHOD          WHAT IT DOES                                   │
│   ─────────────────────────────────────────────────────────────  │
│   append(x)       Add ONE item to END                           │
│                   list.append(5) → [1,2,3,5]                    │
│                                                                  │
│   extend(list)    Add MULTIPLE items to END                     │
│                   list.extend([4,5]) → [1,2,3,4,5]              │
│                                                                  │
│   insert(i, x)    Add ONE item at INDEX i                       │
│                   list.insert(1, 5) → [1,5,2,3]                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Removing Items
#### remove() - Remove by Value
```python
# remove(value) - Removes FIRST occurrence of value

ports = [22, 80, 443, 80, 8080]
print(f"Before: {ports}")      # [22, 80, 443, 80, 8080]

# Remove value 80 (first occurrence)
ports.remove(80)
print(f"After: {ports}")       # [22, 443, 80, 8080]

# Remove again
ports.remove(80)
print(f"After: {ports}")       # [22, 443, 8080]

# Remove value that doesn't exist - ERROR!
# ports.remove(9999)           # ValueError!

# Safe removal - check first
if 9999 in ports:
    ports.remove(9999)
else:
    print("9999 not in list")
```

#### pop() - Remove by Index
```python
# pop(index) - Removes item at index and RETURNS it
# pop() with no argument removes LAST item

ports = [22, 80, 443, 8080]
print(f"Before: {ports}")      # [22, 80, 443, 8080]

# Pop last item (no argument)
removed = ports.pop()
print(f"Removed: {removed}")   # 8080
print(f"After: {ports}")       # [22, 80, 443]

# Pop at specific index
removed = ports.pop(1)
print(f"Removed: {removed}")   # 80
print(f"After: {ports}")       # [22, 443]

# Pop first item
removed = ports.pop(0)
print(f"Removed: {removed}")   # 22
print(f"After: {ports}")       # [443]

# Pop from empty list - ERROR!
empty = []
# empty.pop()                  # IndexError!
```

#### clear() - Remove All Items
```python
# clear() - Removes ALL items

ports = [22, 80, 443, 8080]
print(f"Before: {ports}")      # [22, 80, 443, 8080]
print(f"Length: {len(ports)}") # 4

ports.clear()
print(f"After: {ports}")       # []
print(f"Length: {len(ports)}") # 0
```

#### del Statement
```python
# del - Delete items or entire list

ports = [21, 22, 23, 80, 443]

# Delete single item
del ports[0]
print(ports)           # [22, 23, 80, 443]

# Delete range of items
del ports[1:3]
print(ports)           # [22, 443]

# Delete entire list (variable is gone!)
del ports
# print(ports)         # ERROR! NameError: name 'ports' is not defined
```

##### Comparison: remove vs pop vs clear vs del
```
┌─────────────────────────────────────────────────────────────────┐
│           REMOVING ITEMS - COMPARISON                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   METHOD              WHAT IT DOES                               │
│   ─────────────────────────────────────────────────────────────  │
│   remove(value)       Remove first item with that VALUE         │
│                       list.remove(80)                           │
│                                                                  │
│   pop(index)          Remove item at INDEX, return it           │
│                       x = list.pop(2)                           │
│                                                                  │
│   pop()               Remove LAST item, return it               │
│                       x = list.pop()                            │
│                                                                  │
│   clear()             Remove ALL items (empty list)             │
│                       list.clear()                              │
│                                                                  │
│   del list[i]         Delete item at index (no return)          │
│                       del list[2]                               │
│                                                                  │
│   del list[i:j]       Delete range of items                     │
│                       del list[1:4]                             │
│                                                                  │
│   del list            Delete the entire list variable           │
│                       del list                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Finding Items
#### index() - Find Position
```python
# index(value) - Returns index of FIRST occurrence

ports = [22, 80, 443, 80, 8080]

# Find index of value
print(ports.index(443))       # 2
print(ports.index(80))        # 1 (first occurrence)

# Value not found - ERROR!
# print(ports.index(9999))    # ValueError!

# Safe way - check first
if 9999 in ports:
    print(ports.index(9999))
else:
    print("9999 not found")

# Search within range
# index(value, start, stop)
ports = [22, 80, 443, 80, 8080]
print(ports.index(80, 2))     # 3 (search from index 2)
```

#### count() - Count Occurrences
```python
# count(value) - Returns number of times value appears

ports = [22, 80, 443, 80, 8080, 80]

print(ports.count(80))        # 3
print(ports.count(22))        # 1
print(ports.count(9999))      # 0 (not found, no error)

# Count in a log analysis
log_levels = ["INFO", "ERROR", "INFO", "WARNING", "ERROR", "ERROR", "INFO"]

print(f"INFO count: {log_levels.count('INFO')}")       # 3
print(f"ERROR count: {log_levels.count('ERROR')}")     # 3
print(f"WARNING count: {log_levels.count('WARNING')}") # 1
```

## Ordering Items
#### sort() - Sort In Place
```python
# sort() - Sorts the list IN PLACE (modifies original)

ports = [443, 22, 8080, 80, 21]
print(f"Before: {ports}")      # [443, 22, 8080, 80, 21]

ports.sort()
print(f"After: {ports}")       # [21, 22, 80, 443, 8080]

# Sort in reverse (descending)
ports.sort(reverse=True)
print(f"Descending: {ports}")  # [8080, 443, 80, 22, 21]

# Sort strings
names = ["Charlie", "Alice", "Bob"]
names.sort()
print(names)                   # ['Alice', 'Bob', 'Charlie']

# Sort strings (case-insensitive)
mixed = ["banana", "Apple", "cherry"]
mixed.sort()                   # Uppercase comes first!
print(mixed)                   # ['Apple', 'banana', 'cherry']

mixed.sort(key=str.lower)      # Case-insensitive
print(mixed)                   # ['Apple', 'banana', 'cherry']
```

#### reverse() - Reverse In Place
```python
# reverse() - Reverses the list IN PLACE

ports = [22, 80, 443]
print(f"Before: {ports}")      # [22, 80, 443]

ports.reverse()
print(f"After: {ports}")       # [443, 80, 22]

# Alternative: slicing (creates new list)
ports = [22, 80, 443]
reversed_ports = ports[::-1]
print(reversed_ports)          # [443, 80, 22]
print(ports)                   # [22, 80, 443] (original unchanged)
```

#### sorted() - Create Sorted Copy
```python
# sorted() - Returns a NEW sorted list (original unchanged)

ports = [443, 22, 8080, 80]
print(f"Original: {ports}")

# Create sorted copy
sorted_ports = sorted(ports)
print(f"Sorted copy: {sorted_ports}")   # [22, 80, 443, 8080]
print(f"Original: {ports}")              # [443, 22, 8080, 80] (unchanged!)

# Descending
sorted_desc = sorted(ports, reverse=True)
print(f"Descending: {sorted_desc}")      # [8080, 443, 80, 22]
```


##### comparison sort() vs sorted()  
```
┌─────────────────────────────────────────────────────────────────┐
│           sort() vs sorted()                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   sort()                      sorted()                           │
│   ─────────────────────────   ─────────────────────────────     │
│   Method of list              Built-in function                  │
│   Modifies original           Creates new list                   │
│   Returns None                Returns sorted list                │
│   list.sort()                 sorted(list)                       │
│                                                                  │
│   Example:                    Example:                           │
│   nums = [3,1,2]              nums = [3,1,2]                     │
│   nums.sort()                 new = sorted(nums)                 │
│   print(nums) → [1,2,3]       print(new) → [1,2,3]              │
│                               print(nums) → [3,1,2]              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


# Summary
```
┌─────────────────────────────────────────────────────────────────┐
│                  SUMMARY                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CREATING LISTS:                                                 │
│  • list = [1, 2, 3]                                             │
│  • list = list(range(5))                                        │
│  • list = []  (empty)                                           │
│                                                                  │
│  CHARACTERISTICS:                                                │
│  • Ordered (has index)                                          │
│  • Mutable (can change)                                         │
│  • Allows duplicates                                            │
│  • Mixed data types allowed                                     │
│                                                                  │
│  INDEXING & SLICING:                                             │
│  • list[0]  (first item)                                        │
│  • list[-1] (last item)                                         │
│  • list[1:4] (slice)                                            │
│  • list[::-1] (reverse)                                         │
│                                                                  │
│  ADDING ITEMS:                                                   │
│  • append(x)     - add one to end                               │
│  • extend(list)  - add multiple to end                          │
│  • insert(i, x)  - add at index i                               │
│                                                                  │
│  REMOVING ITEMS:                                                 │
│  • remove(x)  - remove by value                                 │
│  • pop(i)     - remove by index (returns it)                    │
│  • pop()      - remove last (returns it)                        │
│  • clear()    - remove all                                      │
│  • del list[i]                                                  │
│                                                                  │
│  FINDING ITEMS:                                                  │
│  • index(x)  - find position                                    │
│  • count(x)  - count occurrences                                │
│  • x in list - check existence                                  │
│                                                                  │
│  ORDERING:                                                       │
│  • sort()           - sort in place                             │
│  • sort(reverse=True) - descending                              │
│  • reverse()        - reverse in place                          │
│  • sorted(list)     - return new sorted list                    │
│                                                                  │
│  OTHER:                                                          │
│  • len(list), min(), max(), sum()                               │
│  • copy() or list[:] - create copy                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```