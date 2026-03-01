
# Module 20: Flow Control Statements

## What is Flow Control?

Flow control means deciding which code to run based on conditions.

**Without flow control:**
- Code runs line by line, top to bottom

**With flow control:**
- Code can make decisions
- Code can skip some lines
- Code can choose different paths

---

## The if Statement

### Basic Syntax

```python
if condition:
    # code runs if condition is True
```

### Simple Example

```python
age = 18

if age >= 18:
    print("You are an adult")
```

Output:
```
You are an adult
```

### More Examples

```python
# Check if port is open
port = 22

if port == 22:
    print("SSH port detected")
```

```python
# Check if number is positive
num = 10

if num > 0:
    print("Positive number")
```

---

## The if-else Statement

### Basic Syntax

```python
if condition:
    # code runs if condition is True
else:
    # code runs if condition is False
```

### Simple Example

```python
age = 15

if age >= 18:
    print("Adult")
else:
    print("Minor")
```

Output:
```
Minor
```

### More Examples

```python
# Check login
password = "secret123"

if password == "secret123":
    print("Login successful")
else:
    print("Login failed")
```

```python
# Check even or odd
num = 7

if num % 2 == 0:
    print("Even")
else:
    print("Odd")
```

Output:
```
Odd
```

---

## The if-elif-else Statement

### What is elif?

- `elif` means "else if"
- Used to check multiple conditions
- Can have many `elif` blocks

### Basic Syntax

```python
if condition1:
    # runs if condition1 is True
elif condition2:
    # runs if condition2 is True
elif condition3:
    # runs if condition3 is True
else:
    # runs if all conditions are False
```

### Simple Example

```python
marks = 75

if marks >= 90:
    print("Grade A")
elif marks >= 80:
    print("Grade B")
elif marks >= 70:
    print("Grade C")
elif marks >= 60:
    print("Grade D")
else:
    print("Grade F")
```

Output:
```
Grade C
```

### Port Checker Example

```python
port = 443

if port == 22:
    print("SSH")
elif port == 80:
    print("HTTP")
elif port == 443:
    print("HTTPS")
elif port == 21:
    print("FTP")
else:
    print("Unknown port")
```

Output:
```
HTTPS
```

### Login Status Example

```python
status = "blocked"

if status == "active":
    print("User can login")
elif status == "inactive":
    print("Account inactive")
elif status == "blocked":
    print("Account blocked")
else:
    print("Unknown status")
```

Output:
```
Account blocked
```

---

## Nested Conditions

### What is Nesting?

- Putting one `if` inside another `if`
- Used for checking multiple related conditions

### Basic Syntax

```python
if condition1:
    if condition2:
        # runs if both conditions are True
```

### Simple Example

```python
age = 25
has_id = True

if age >= 18:
    if has_id:
        print("Entry allowed")
    else:
        print("Show your ID")
else:
    print("Too young")
```

Output:
```
Entry allowed
```

### Login Example

```python
username = "admin"
password = "secret123"

if username == "admin":
    if password == "secret123":
        print("Login successful")
    else:
        print("Wrong password")
else:
    print("User not found")
```

Output:
```
Login successful
```

---

## Ternary Operator

### What is Ternary?

- One-line `if-else` statement
- Shorter way to write simple conditions

### Basic Syntax

```python
result = value_if_true if condition else value_if_false
```

### Simple Example

```python
age = 20

status = "Adult" if age >= 18 else "Minor"
print(status)
```

Output:
```
Adult
```

### More Examples

```python
# Check positive or negative
num = -5
result = "Positive" if num > 0 else "Negative"
print(result)    # Negative
```

```python
# Check even or odd
num = 10
result = "Even" if num % 2 == 0 else "Odd"
print(result)    # Even
```

```python
# Set port status
port = 22
status = "Open" if port == 22 else "Closed"
print(status)    # Open
```

---

## Comparison: Regular vs Ternary

### Regular if-else

```python
age = 20

if age >= 18:
    status = "Adult"
else:
    status = "Minor"

print(status)
```

### Ternary (Same Result)

```python
age = 20

status = "Adult" if age >= 18 else "Minor"
print(status)
```

Both give same output: `Adult`

---

## Practical Examples

### Example 1: Age Checker

```python
age = 25

if age < 13:
    print("Child")
elif age < 20:
    print("Teenager")
elif age < 60:
    print("Adult")
else:
    print("Senior")
```

### Example 2: Simple Login

```python
username = "admin"
password = "1234"

if username == "admin" and password == "1234":
    print("Welcome, Admin!")
else:
    print("Access Denied!")
```

### Example 3: Port Scanner Output

```python
port = 80
status = "open"

if status == "open":
    if port == 22:
        print("SSH is open")
    elif port == 80:
        print("HTTP is open")
    elif port == 443:
        print("HTTPS is open")
    else:
        print(f"Port {port} is open")
else:
    print(f"Port {port} is closed")
```

### Example 4: Check IP Type

```python
ip = "192.168.1.1"

if ip.startswith("192.168"):
    print("Private IP (Class C)")
elif ip.startswith("10."):
    print("Private IP (Class A)")
elif ip.startswith("172."):
    print("Private IP (Class B)")
else:
    print("Public IP")
```

---

## Common Mistakes

### Mistake 1: Using = instead of ==

```python
# WRONG
if age = 18:    # This is assignment, not comparison!

# CORRECT
if age == 18:   # This is comparison
```

### Mistake 2: Forgetting Colon

```python
# WRONG
if age >= 18
    print("Adult")

# CORRECT
if age >= 18:
    print("Adult")
```

### Mistake 3: Wrong Indentation

```python
# WRONG
if age >= 18:
print("Adult")    # Not indented!

# CORRECT
if age >= 18:
    print("Adult")    # Properly indented
```

---

## Quick Reference

### if Statement

```python
if condition:
    # code
```

### if-else Statement

```python
if condition:
    # code if True
else:
    # code if False
```

### if-elif-else Statement

```python
if condition1:
    # code
elif condition2:
    # code
else:
    # code
```

### Nested if

```python
if condition1:
    if condition2:
        # code
```

### Ternary Operator

```python
result = value1 if condition else value2
```

---

## Summary

| Statement | Use |
|-----------|-----|
| `if` | Check one condition |
| `if-else` | Choose between two options |
| `if-elif-else` | Choose between many options |
| Nested `if` | Check conditions inside conditions |
| Ternary | One-line if-else |

### Key Points

- Use `==` for comparison (not `=`)
- Always use colon `:` after condition
- Indent code inside `if` blocks
- `elif` is short for "else if"
- Ternary is just a shorter `if-else`
