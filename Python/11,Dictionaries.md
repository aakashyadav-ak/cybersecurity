# DICTIONARY
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT IS A DICTIONARY?                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   A DICTIONARY is a collection of KEY-VALUE pairs.              │
│                                                                  │
│   Think of it like a real dictionary:                            │
│   • Word (key) → Definition (value)                              │
│                                                                  │
│   Or like a contact list:                                        │
│   • Name (key) → Phone Number (value)                            │
│                                                                  │
│   ┌─────────────────────────────────────────┐                   │
│   │  KEY         →    VALUE                 │                   │
│   ├─────────────────────────────────────────┤                   │
│   │  "name"      →    "Alice"               │                   │
│   │  "age"       →    25                    │                   │
│   │  "is_admin"  →    True                  │                   │
│   └─────────────────────────────────────────┘                   │
│                                                                  │
│   In Python: {"name": "Alice", "age": 25, "is_admin": True}     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


## Dictionary Definition
### Creating Dictionaries
```python
# Dictionaries use curly braces { } with key:value pairs

# Basic dictionary
person = {
    "name": "Alice",
    "age": 25,
    "city": "New York"
}

# Single line
user = {"username": "admin", "password": "secret123"}

# Empty dictionary
empty_dict = {}

# Check type
print(type(person))    # <class 'dict'>
```

### Dictionary Syntax
```
┌─────────────────────────────────────────────────────────────────┐
│                    DICTIONARY SYNTAX                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   {                                                              │
│       key1: value1,                                              │
│       key2: value2,                                              │
│       key3: value3                                               │
│   }                                                              │
│                                                                  │
│   Rules:                                                         │
│   • Keys and values separated by colon :                        │
│   • Pairs separated by comma ,                                  │
│   • Keys must be UNIQUE                                         │
│   • Keys must be IMMUTABLE (string, number, tuple)              │
│   • Values can be ANY type                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Different Ways to Create Dictionaries
```python
# Method 1: Curly braces { }
person = {"name": "Alice", "age": 25}

# Method 2: dict() constructor with keyword arguments
person = dict(name="Alice", age=25)
print(person)    # {'name': 'Alice', 'age': 25}

# Method 3: dict() with list of tuples
person = dict([("name", "Alice"), ("age", 25)])
print(person)    # {'name': 'Alice', 'age': 25}

# Method 4: dict.fromkeys() - create with default values
keys = ["a", "b", "c"]
my_dict = dict.fromkeys(keys, 0)
print(my_dict)   # {'a': 0, 'b': 0, 'c': 0}

# Method 5: Dictionary comprehension
squares = {x: x**2 for x in range(1, 6)}
print(squares)   # {1: 1, 2: 4, 3: 9, 4: 16, 5: 25}
```

#### Keys Must Be Unique
```python
# If duplicate keys, last value wins!

data = {
    "port": 80,
    "port": 443,     # Duplicate key!
    "port": 8080     # Duplicate key!
}

print(data)          # {'port': 8080} - Only last value kept!
print(len(data))     # 1
```

## Characteristics of Dictionaries
```
┌─────────────────────────────────────────────────────────────────┐
│              CHARACTERISTICS OF DICTIONARIES                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. KEY-VALUE PAIRS                                             │
│      • Each item has a key and a value                           │
│      • Access values using keys (not index)                      │
│                                                                  │
│   2. UNORDERED (Python 3.6 and earlier)                          │
│      ORDERED (Python 3.7+)                                       │
│      • Maintains insertion order in Python 3.7+                  │
│                                                                  │
│   3. MUTABLE                                                     │
│      • Can add, remove, modify items                             │
│                                                                  │
│   4. NO DUPLICATE KEYS                                           │
│      • Each key must be unique                                   │
│      • Values can be duplicated                                  │
│                                                                  │
│   5. KEYS MUST BE IMMUTABLE                                      │
│      • Strings, numbers, tuples only                            │
│      • Lists, dicts cannot be keys                              │
│                                                                  │
│   6. FAST LOOKUP                                                 │
│      • O(1) time complexity for access                          │
│      • Very efficient for large data                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


### Accessing Dictionary Items
#### Using Keys with [ ]
```python
user = {
    "username": "admin",
    "email": "admin@example.com",
    "role": "administrator"
}

# Access value using key
print(user["username"])     # admin
print(user["email"])        # admin@example.com
print(user["role"])         # administrator

# Key not found - ERROR!
# print(user["password"])   # KeyError: 'password'
```

#### Using get() Method 
```python
user = {
    "username": "admin",
    "email": "admin@example.com"
}

# get() returns None if key not found (no error!)
print(user.get("username"))     # admin
print(user.get("password"))     # None (no error!)

# get() with default value
print(user.get("password", "N/A"))           # N/A
print(user.get("role", "user"))              # user
print(user.get("username", "unknown"))       # admin (key exists)

# Comparison: [] vs get()
# user["password"]           # KeyError!
# user.get("password")       # None (safe)
```

## Adding & Modifying Items
### Adding New Items
```python
# Method 1: Using [ ] with new key
user = {"username": "admin"}

user["email"] = "admin@example.com"
user["role"] = "administrator"

print(user)
# {'username': 'admin', 'email': 'admin@example.com', 'role': 'administrator'}

# Method 2: Using update() with single item
user.update({"is_active": True})
print(user)
```

### Modifying Existing Items
```python
user = {
    "username": "admin",
    "login_attempts": 0,
    "is_locked": False
}

print(f"Before: {user}")

# Modify using [ ]
user["login_attempts"] = 3
user["is_locked"] = True

print(f"After: {user}")
# {'username': 'admin', 'login_attempts': 3, 'is_locked': True}
```

## Removing Items
#### pop() Method
```python
# pop(key) - Remove item by key and return its value

user = {
    "username": "admin",
    "email": "admin@example.com",
    "role": "administrator",
    "temp_token": "abc123"
}

# Remove and get value
removed = user.pop("temp_token")
print(f"Removed: {removed}")     # Removed: abc123
print(f"User: {user}")           # temp_token is gone

# pop() with key that doesn't exist - ERROR!
# user.pop("password")           # KeyError!

# pop() with default value (no error)
result = user.pop("password", "not found")
print(result)                    # not found
```

### del Keyword
```python
# del - Delete item by key

user = {
    "username": "admin",
    "email": "admin@example.com",
    "password": "secret123"
}

# Delete single item
del user["password"]
print(user)    # {'username': 'admin', 'email': 'admin@example.com'}

# Delete key that doesn't exist - ERROR!
# del user["age"]    # KeyError: 'age'

# Safe deletion - check first
if "age" in user:
    del user["age"]
else:
    print("Key 'age' not found")

# Delete entire dictionary
del user
# print(user)    # NameError: name 'user' is not defined
```

### clear() Method
```python
# clear() - Remove ALL items (empty the dictionary)

user = {
    "username": "admin",
    "email": "admin@example.com",
    "role": "administrator"
}

print(f"Before: {user}")
print(f"Length: {len(user)}")    # 3

user.clear()

print(f"After: {user}")          # {}
print(f"Length: {len(user)}")    # 0
```

# Summary
```
┌─────────────────────────────────────────────────────────────────┐
│                     SUMMARY                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DICTIONARY DEFINITION:                                          │
│  • Key-value pairs in curly braces { }                          │
│  • my_dict = {"key": "value"}                                   │
│  • Keys must be unique and immutable                            │
│                                                                  │
│  ACCESSING ITEMS:                                                │
│  • dict["key"]           - get value (error if missing)         │
│  • dict.get("key")       - get value (None if missing)          │
│  • dict.get("key", default) - with default value                │
│  • "key" in dict         - check if key exists                  │
│                                                                  │
│  ADDING / MODIFYING:                                             │
│  • dict["new_key"] = value    - add or update                   │
│  • dict.update({...})         - add/update multiple             │
│                                                                  │
│  REMOVING ITEMS:                                                 │
│  • pop(key)       - remove by key, return value                 │
│  • popitem()      - remove last item                            │
│  • del dict[key]  - delete by key                               │
│  • clear()        - remove all items                            │
│                                                                  │
│  KEY METHODS:                                                    │
│  • keys()    - get all keys                                     │
│  • values()  - get all values                                   │
│  • items()   - get all (key, value) pairs                       │
│  • copy()    - create shallow copy                              │
│  • setdefault(key, default)                                     │
│                                                                  │
│  ITERATION:                                                      │
│  • for key in dict:                                             │
│  • for key in dict.keys():                                      │
│  • for value in dict.values():                                  │
│  • for key, value in dict.items():                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```