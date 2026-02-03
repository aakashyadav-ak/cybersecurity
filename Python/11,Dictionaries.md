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

#### 