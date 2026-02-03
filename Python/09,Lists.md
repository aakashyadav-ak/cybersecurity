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