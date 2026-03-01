```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT ARE OPERATORS?                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Operators are symbols that perform operations on values.      │
│                                                                  │
│   Example:                                                       │
│       5 + 3 = 8                                                 │
│       ↑   ↑                                                      │
│    operand  operator                                            │
│                                                                  │
│   Types of operators:                                            │
│   • Arithmetic    (+, -, *, /)                                  │
│   • Comparison    (==, !=, >, <)                                │
│   • Logical       (and, or, not)                                │
│   • Assignment    (=, +=, -=)                                   │
│   • Membership    (in, not in)                                  │
│   • Identity      (is, is not)                                  │
│   • Bitwise       (&, |, ^)                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


## 1. Arithmetic Operators

```
┌──────────┬─────────────────┬─────────────────┐
│ Operator │ Name            │ Example         │
├──────────┼─────────────────┼─────────────────┤
│    +     │ Addition        │ 5 + 3 = 8       │
│    -     │ Subtraction     │ 5 - 3 = 2       │
│    *     │ Multiplication  │ 5 * 3 = 15      │
│    /     │ Division        │ 5 / 2 = 2.5     │
│    //    │ Floor Division  │ 5 // 2 = 2      │
│    %     │ Modulus         │ 5 % 2 = 1       │
│    **    │ Exponent        │ 5 ** 2 = 25     │
└──────────┴─────────────────┴─────────────────┘
```

### Examples

```python
# Basic operations
print(10 + 5)     # 15
print(10 - 3)     # 7
print(4 * 5)      # 20
print(10 / 4)     # 2.5 (always gives float)
print(10 // 4)    # 2 (removes decimal)
print(10 % 3)     # 1 (remainder)
print(2 ** 3)     # 8 (2 × 2 × 2)
```
#### Addition (+)

```python
a = 10
b = 5

result = a + b
print(result)    # 15

# More examples
print(3 + 7)     # 10
print(100 + 50)  # 150
```


#### Subtraction (-)


```python
a = 10
b = 3

result = a - b
print(result)    # 7

# More examples
print(20 - 8)    # 12
print(5 - 10)    # -5
```


#### Multiplication (*)


```python
a = 4
b = 5

result = a * b
print(result)    # 20

# More examples
print(7 * 3)     # 21
print(10 * 10)   # 100
```



#### Division (/)

```python
a = 10
b = 4

result = a / b
print(result)    # 2.5

# Division ALWAYS gives float!
print(10 / 2)    # 5.0 (not 5)
print(9 / 3)     # 3.0
```



#### Floor Division (//)

```python
# Removes decimal part (gives integer)

a = 10
b = 3

result = a // b
print(result)    # 3 (not 3.33)

# More examples
print(17 // 5)   # 3
print(10 // 4)   # 2
print(7 // 2)    # 3
```




#### Modulus (%)


# Gives the REMAINDER after division

```python
a = 10
b = 3

result = a % b
print(result)    # 1 (because 10 = 3*3 + 1)

# More examples
print(17 % 5)    # 2 (17 = 5*3 + 2)
print(10 % 2)    # 0 (no remainder = even number)
print(11 % 2)    # 1 (has remainder = odd number)
```



#### Checking Even or Odd
```python
# If number % 2 == 0, it's EVEN
# If number % 2 == 1, it's ODD

num = 10
if num % 2 == 0:
    print("Even")
else:
    print("Odd")
```



#### Exponent (**)

```python
# Power: a ** b means "a to the power of b"

print(2 ** 3)    # 8 (2 × 2 × 2)
print(5 ** 2)    # 25 (5 × 5)
print(10 ** 3)   # 1000 (10 × 10 × 10)
print(4 ** 0.5)  # 2.0 (square root of 4)

```




## 2. Comparison Operators

Used to compare values. Returns True or False.

| Operator | Name             | Example          |
|----------|------------------|------------------|
| `==`     | Equal to         | 5 == 5 → True    |
| `!=`     | Not equal to     | 5 != 3 → True    |
| `>`      | Greater than     | 5 > 3 → True     |
| `<`      | Less than        | 5 < 3 → False    |
| `>=`     | Greater or equal | 5 >= 5 → True    |
| `<=`     | Less or equal    | 5 <= 3 → False   |
#### Equal (= =)


```
print(5 == 5)      # True
print(5 == 3)      # False
print("hello" == "hello")  # True
print("Hello" == "hello")  # False (case matters!)
```

#### Not Equal (!=)

```
print(5 != 3)      # True (5 is not equal to 3)
print(5 != 5)      # False (5 IS equal to 5)
print("a" != "b")  # True
```


#### Greater Than (>)

```
print(10 > 5)      # True
print(5 > 10)      # False
print(5 > 5)       # False (not greater, equal)
```



#### Less Than (<)
```
print(3 < 10)      # True
print(10 < 3)      # False
print(5 < 5)       # False (not less, equal)
```
#### Greater or Equal (>=)

```
print(10 >= 5)     # True
print(5 >= 5)      # True (equal counts!)
print(3 >= 5)      # False
```


#### Less or Equal (<=)

```
print(3 <= 5)      # True
print(5 <= 5)      # True (equal counts!)
print(10 <= 5)     # False
```


#### Using in if Statements

```python
age = 18

if age >= 18:
    print("Adult")
else:
    print("Minor")
# Output: Adult

port = 22
if port == 22:
    print("SSH port")
# Output: SSH port
```



## 3. Logical Operators
Used to combine conditions.

| Operator | Description           | Example                |
|----------|-----------------------|------------------------|
| `and`    | True if BOTH are True | True and True → True   |
| `or`     | True if ANY is True   | True or False → True   |
| `not`    | Reverses the result   | not True → False       |
#### and Operator

```
# Both must be True

print(True and True)     # True
print(True and False)    # False
print(False and True)    # False
print(False and False)   # False
```


```
# Practical example
age = 25
has_id = True

if age >= 18 and has_id:
    print("Can enter")
else:
    print("Cannot enter")
# Output: Can enter
```




#### or Operator

```
# At least one must be True

print(True or True)      # True
print(True or False)     # True
print(False or True)     # True
print(False or False)    # False
```


```
# Practical example
is_admin = False
is_moderator = True

if is_admin or is_moderator:
    print("Has access")
else:
    print("No access")
# Output: Has access
```

#### not Operator
```
# Reverses True/False

print(not True)          # False
print(not False)         # True
```


```
# Practical example
is_blocked = False

if not is_blocked:
    print("User can login")
else:
    print("User is blocked")
# Output: User can login
```


#### Combining Logical Operators

```python
username = "admin"
password = "secret123"
is_active = True

# Check all conditions
if username == "admin" and password == "secret123" and is_active:
    print("Login successful!")
else:
    print("Login failed!")
# Output: Login successful!
```


## 4. Assignment Operators

Used to assign values to variables.

```
┌──────────┬─────────────────┬─────────────────────┐
│ Operator │ Example         │ Same As             │
├──────────┼─────────────────┼─────────────────────┤
│    =     │ x = 5           │ x = 5               │
│   +=     │ x += 3          │ x = x + 3           │
│   -=     │ x -= 3          │ x = x - 3           │
│   *=     │ x *= 3          │ x = x * 3           │
│   /=     │ x /= 3          │ x = x / 3           │
│   //=    │ x //= 3         │ x = x // 3          │
│   %=     │ x %= 3          │ x = x % 3           │
│   **=    │ x **= 3         │ x = x ** 3          │
└──────────┴─────────────────┴─────────────────────┘
```

**Basic Assignment (=)**
```
x = 10
name = "Alice"
is_valid = True
```

#### Add and Assign (+=)
```
x = 10
x += 5      # Same as: x = x + 5
print(x)    # 15

# Counting example
count = 0
count += 1  # count is now 1
count += 1  # count is now 2
count += 1  # count is now 3
print(count)  # 3
```



#### Subtract and Assign (-=)
```Python

x = 10
x -= 3      # Same as: x = x - 3
print(x)    # 7

# Countdown example
lives = 3
lives -= 1  # lives is now 2
print(lives)  # 2
```



#### Multiply and Assign (*=)
```Python

x = 5
x *= 2      # Same as: x = x * 2
print(x)    # 10
```



#### Divide and Assign (/=)
```Python

x = 20
x /= 4      # Same as: x = x / 4
print(x)    # 5.0
```


#### String with +=
```Python

message = "Hello"
message += " World"    # Same as: message = message + " World"
print(message)         # Hello World
```



## 5. Membership Operators
Check if value exists in a sequence (list, string, tuple, etc.)

```
┌──────────┬────────────────────────────────────┐
│ Operator │ Description                        │
├──────────┼────────────────────────────────────┤
│   in     │ True if value is in sequence      │
│  not in  │ True if value is NOT in sequence  │
└──────────┴────────────────────────────────────┘
```




#### in Operator
```Python

# Check if item is in list
ports = [22, 80, 443]

print(22 in ports)      # True
print(8080 in ports)    # False
```


```Python

# Check if character is in string
text = "Hello World"

print("H" in text)      # True
print("x" in text)      # False
print("World" in text)  # True
```


#### not in Operator
```Python

ports = [22, 80, 443]

print(8080 not in ports)   # True (8080 is NOT in list)
print(22 not in ports)     # False (22 IS in list)
```

##### Practical Examples
```Python

# Check if port is open
open_ports = [22, 80, 443]
target_port = 80

if target_port in open_ports:
    print(f"Port {target_port} is open")
else:
    print(f"Port {target_port} is closed")
# Output: Port 80 is open
```

```Python

# Check if IP is blocked
blocked_ips = ["192.168.1.100", "10.0.0.50"]
user_ip = "192.168.1.1"

if user_ip in blocked_ips:
    print("Access denied!")
else:
    print("Access granted!")
# Output: Access granted!
```
Python




## 6. Identity Operators
Check if two variables point to the SAME object in memory.

```
┌──────────┬────────────────────────────────────┐
│ Operator │ Description                        │
├──────────┼────────────────────────────────────┤
│   is     │ True if same object                │
│  is not  │ True if not same object            │
└──────────┴────────────────────────────────────┘
```



#### is Operator
```Python

# Most common use: checking for None

result = None

if result is None:
    print("No result yet")
# Output: No result yet
```



#### is vs ==
```Python

# == checks VALUE
# is checks IDENTITY (same object)

a = [1, 2, 3]
b = [1, 2, 3]
c = a

print(a == b)    # True (same values)
print(a is b)    # False (different objects)
print(a is c)    # True (same object)
```



#### When to Use is
```Python

# Use 'is' for:
# - None
# - True/False

x = None
if x is None:
    print("x is None")

y = True
if y is True:
    print("y is True")
```


## 7. Bitwise Operators
Work on binary (bits). Used in low-level programming.

```
┌──────────┬─────────────────┐
│ Operator │ Name            │
├──────────┼─────────────────┤
│    &     │ AND             │
│    |     │ OR              │
│    ^     │ XOR             │
│    ~     │ NOT             │
│    <<    │ Left shift      │
│    >>    │ Right shift     │
└──────────┴─────────────────┘
```



**Simple Examples**
```Python

a = 5      # Binary: 101
b = 3      # Binary: 011

print(a & b)    # 1 (AND)
print(a | b)    # 7 (OR)
print(a ^ b)    # 6 (XOR)
```


**Basic Understanding**
```
    5 in binary:  101
    3 in binary:  011
    
    AND (&):      001 = 1  (both bits must be 1)
    OR  (|):      111 = 7  (at least one bit is 1)
    XOR (^):      110 = 6  (bits must be different)
```


#### Security Use: Simple XOR
```Python
# XOR is used in simple encryption

message = 65      # ASCII for 'A'
key = 10

encrypted = message ^ key
print(encrypted)   # 75

decrypted = encrypted ^ key
print(decrypted)   # 65 (back to original!)
```



# Summary
```
┌─────────────────────────────────────────────────────────────────┐
│                    MODULE 18 SUMMARY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ARITHMETIC:  +  -  *  /  //  %  **                             │
│                                                                  │
│  COMPARISON:  ==  !=  >  <  >=  <=                              │
│                                                                  │
│  LOGICAL:     and  or  not                                      │
│                                                                  │
│  ASSIGNMENT:  =  +=  -=  *=  /=                                 │
│                                                                  │
│  MEMBERSHIP:  in   not in                                       │
│                                                                  │
│  IDENTITY:    is   is not                                       │
│                                                                  │
│  KEY POINTS:                                                     │
│  • /  gives float, // gives integer                             │
│  • %  gives remainder                                           │
│  • ** is power (2**3 = 8)                                       │
│  • Use parentheses when unsure of order                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```