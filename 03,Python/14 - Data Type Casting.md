
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

## String ↔ Float
```bash
# string → float

price_string = "19.99"
print(type(price_string))    # <class 'str'>

# Convert to float
price = float(price_string)
print(price)                 # 19.99
print(type(price))           # <class 'float'>

# Now we can do math
tax = price * 0.1
print(f"Tax: {tax}")         # Tax: 1.999
```


## Float to String
```bash
# float → string

temperature = 36.6
print(type(temperature))    # <class 'float'>

# Convert to string
temp_string = str(temperature)
print(temp_string)          # 36.6
print(type(temp_string))    # <class 'str'>
```


## Integer ↔ Boolean
```bash
# int → bool

# Rule:
# 0 = False
# Any other number = True

print(bool(0))      # False
print(bool(1))      # True
print(bool(5))      # True
print(bool(100))    # True
print(bool(-1))     # True (any non-zero is True!)
print(bool(-50))    # True
```

#### Rule
```
┌─────────────────────────────────────────────────────────────────┐
│                    INTEGER TO BOOLEAN                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   0        →    False                                           │
│   Non-zero →    True                                            │
│                                                                  │
│   Examples:                                                      │
│   bool(0)   = False                                             │
│   bool(1)   = True                                              │
│   bool(42)  = True                                              │
│   bool(-5)  = True                                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


## Boolean to Integer
```bash
# bool → int

# Rule:
# True = 1
# False = 0

print(int(True))    # 1
print(int(False))   # 0

# Useful for counting!
results = [True, False, True, True, False]
success_count = sum(results)    # Treats True as 1
print(f"Successes: {success_count}")  # Successes: 3
```

## List ↔ Tuple

```bash
# list → tuple

my_list = [1, 2, 3, 4, 5]
print(my_list)          # [1, 2, 3, 4, 5]
print(type(my_list))    # <class 'list'>

# Convert to tuple
my_tuple = tuple(my_list)
print(my_tuple)         # (1, 2, 3, 4, 5)
print(type(my_tuple))   # <class 'tuple'>
```

## Tuple to List
```bash
# tuple → list

my_tuple = (1, 2, 3, 4, 5)
print(my_tuple)         # (1, 2, 3, 4, 5)
print(type(my_tuple))   # <class 'tuple'>

# Convert to list
my_list = list(my_tuple)
print(my_list)          # [1, 2, 3, 4, 5]
print(type(my_list))    # <class 'list'>
```



## String to List
```bash
# string → list (each character becomes an item)

text = "hello"
char_list = list(text)
print(char_list)    # ['h', 'e', 'l', 'l', 'o']

# IP address
ip = "192.168.1.1"
ip_list = list(ip)
print(ip_list)      # ['1', '9', '2', '.', '1', '6', '8', ...]
```



# Summary
```
┌─────────────────────────────────────────────────────────────────┐
│                    MODULE 17 SUMMARY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CONVERSION FUNCTIONS:                                           │
│                                                                  │
│  int()     "25" → 25        10.7 → 10                          │
│  float()   "3.14" → 3.14    10 → 10.0                          │
│  str()     25 → "25"        3.14 → "3.14"                      │
│  bool()    0 → False        1 → True                           │
│  list()    (1,2,3) → [1,2,3]                                   │
│  tuple()   [1,2,3] → (1,2,3)                                   │
│                                                                  │
│  REMEMBER:                                                       │
│  • int() removes decimal (doesn't round)                        │
│  • bool(0) = False, bool(non-zero) = True                      │
│  • Use type() to check data type                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


```bash
# String to Number
int("25")          # 25
float("3.14")      # 3.14

# Number to String
str(25)            # "25"
str(3.14)          # "3.14"

# Integer ↔ Float
float(10)          # 10.0
int(10.7)          # 10

# Boolean
bool(0)            # False
bool(1)            # True
int(True)          # 1
int(False)         # 0

# List ↔ Tuple
tuple([1,2,3])     # (1, 2, 3)
list((1,2,3))      # [1, 2, 3]

# Check type
type(x)            # Shows type of x
```