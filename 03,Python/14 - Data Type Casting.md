
```
┌─────────────────────────────────────────────────────────────────┐
│                    TYPE CASTING                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Type Casting = Converting one data type to another            │
│                                                                  │
│   Examples:                                                      │
│   • String "25" → Integer 25                                    │
│   • Integer 10 → Float 10.0                                     │
│   • Integer 1 → Boolean True                                    │
│                                                                  │
│   Why do we need this?                                           │
│   • input() gives string, but we need number                    │
│   • Math operations need same types                             │
│   • Some functions require specific types                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Type Casting Functions
```
┌─────────────────────────────────────────────────────────────────┐
│                    CASTING FUNCTIONS                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   int()      Convert to integer                                 │
│   float()    Convert to float                                   │
│   str()      Convert to string                                  │
│   bool()     Convert to boolean                                 │
│   list()     Convert to list                                    │
│   tuple()    Convert to tuple                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Integer ↔ Float
```bash
# int → float

x = 10
print(x)           # 10
print(type(x))     # <class 'int'>

# Convert to float
y = float(x)
print(y)           # 10.0
print(type(y))     # <class 'float'>
```

```bash
# Converting integers to floats

a = float(5)       # 5.0
b = float(100)     # 100.0
c = float(0)       # 0.0
d = float(-25)     # -25.0

print(a, b, c, d)
# Output: 5.0 100.0 0.0 -25.0
```

## Float to Integer
```bash
# float → int (removes decimal part!)

x = 10.7
print(x)           # 10.7
print(type(x))     # <class 'float'>

# Convert to integer
y = int(x)
print(y)           # 10 (decimal part removed!)
print(type(y))     # <class 'int'>
```

#### Decimal Part is REMOVED, Not Rounded!
```bash
# int() removes decimal, does NOT round!

print(int(9.1))    # 9
print(int(9.5))    # 9 (not 10!)
print(int(9.9))    # 9 (not 10!)

# For rounding, use round()
print(round(9.5))  # 10
print(round(9.4))  # 9
```

## String ↔ Integer
```bash
# string → int

age_string = "25"
print(age_string)       # 25
print(type(age_string)) # <class 'str'>

# Convert to integer
age_number = int(age_string)
print(age_number)       # 25
print(type(age_number)) # <class 'int'>

# Now we can do math!
print(age_number + 5)   # 30
```

```bash
a = int("10")      # 10
b = int("100")     # 100
c = int("0")       # 0
d = int("-50")     # -50

print(a, b, c, d)
# Output: 10 100 0 -50
```

#### String Must Contain Only Numbers!
```bash
# These work:
int("123")         # 123
int("42")          # 42

# These cause ERROR:
# int("hello")     # ValueError!
# int("12.5")      # ValueError! (has decimal)
# int("10 20")     # ValueError! (has space)
# int("")          # ValueError! (empty)
```


## Integer to String
```bash
# int → string

age = 25
print(age)           # 25
print(type(age))     # <class 'int'>

# Convert to string
age_string = str(age)
print(age_string)    # 25
print(type(age_string))  # <class 'str'>

# Now we can concatenate with other strings
message = "I am " + age_string + " years old"
print(message)       # I am 25 years old
```