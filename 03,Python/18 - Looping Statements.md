

## What are Loops?

Loops let you run the same code multiple times.

**Without loops:**
```python
print("Hello")
print("Hello")
print("Hello")
```

**With loops:**
```python
for i in range(3):
    print("Hello")
```

Both give same output, but loop is shorter!

---

## Types of Loops

| Loop | Use |
|------|-----|
| `for` | When you know how many times to repeat |
| `while` | When you don't know how many times |

---

## The for Loop

### Basic Syntax

```python
for item in sequence:
    # code to repeat
```

### Loop Through a List

```python
ports = [22, 80, 443]

for port in ports:
    print(port)
```

Output:
```
22
80
443
```

### Loop Through a String

```python
word = "Hello"

for letter in word:
    print(letter)
```

Output:
```
H
e
l
l
o
```

### More Examples

```python
# List of IPs
ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

for ip in ips:
    print(f"Scanning {ip}")
```

Output:
```
Scanning 192.168.1.1
Scanning 192.168.1.2
Scanning 192.168.1.3
```

```python
# List of users
users = ["admin", "guest", "root"]

for user in users:
    print(f"User: {user}")
```

Output:
```
User: admin
User: guest
User: root
```

---

## The range() Function

### What is range()?

`range()` creates a sequence of numbers.

### Basic Syntax

| Syntax | Meaning |
|--------|---------|
| `range(5)` | 0, 1, 2, 3, 4 |
| `range(1, 5)` | 1, 2, 3, 4 |
| `range(1, 10, 2)` | 1, 3, 5, 7, 9 |

### range(stop)

```python
# range(5) = 0, 1, 2, 3, 4

for i in range(5):
    print(i)
```

Output:
```
0
1
2
3
4
```

### range(start, stop)

```python
# range(1, 5) = 1, 2, 3, 4

for i in range(1, 5):
    print(i)
```

Output:
```
1
2
3
4
```

### range(start, stop, step)

```python
# range(1, 10, 2) = 1, 3, 5, 7, 9

for i in range(1, 10, 2):
    print(i)
```

Output:
```
1
3
5
7
9
```

### Practical Examples

```python
# Print "Hello" 3 times
for i in range(3):
    print("Hello")
```

```python
# Count from 1 to 5
for i in range(1, 6):
    print(i)
```

```python
# Scan ports 20 to 25
for port in range(20, 26):
    print(f"Scanning port {port}")
```

Output:
```
Scanning port 20
Scanning port 21
Scanning port 22
Scanning port 23
Scanning port 24
Scanning port 25
```

---

## The while Loop

### Basic Syntax

```python
while condition:
    # code to repeat
```

### Simple Example

```python
count = 1

while count <= 5:
    print(count)
    count += 1
```

Output:
```
1
2
3
4
5
```

### How it Works

1. Check condition
2. If True, run code
3. Go back to step 1
4. If False, stop

### More Examples

```python
# Countdown
num = 5

while num > 0:
    print(num)
    num -= 1

print("Done!")
```

Output:
```
5
4
3
2
1
Done!
```

```python
# Keep asking until correct
password = ""

while password != "secret":
    password = input("Enter password: ")

print("Access granted!")
```

---

## for vs while

| for Loop | while Loop |
|----------|------------|
| Know how many times | Don't know how many times |
| Loop through items | Loop until condition is False |
| Safer (always ends) | Can be infinite if not careful |

### Same Result, Different Loop

```python
# Using for
for i in range(5):
    print(i)

# Using while
i = 0
while i < 5:
    print(i)
    i += 1
```

Both print: 0, 1, 2, 3, 4

---

## Infinite Loop

### What is Infinite Loop?

A loop that never stops.

### Example (Don't run this!)

```python
# This runs forever!
while True:
    print("Running...")
```

### How to Stop?

Press `Ctrl + C` to stop the program.

### Safe Infinite Loop

```python
# With a way to exit
while True:
    answer = input("Continue? (yes/no): ")
    
    if answer == "no":
        break    # Exit the loop
    
    print("Continuing...")

print("Loop ended!")
```

---

## Nested Loops

### What is Nesting?

A loop inside another loop.

### Basic Example

```python
for i in range(3):
    for j in range(2):
        print(f"i={i}, j={j}")
```

Output:
```
i=0, j=0
i=0, j=1
i=1, j=0
i=1, j=1
i=2, j=0
i=2, j=1
```

### Simple Pattern

```python
for i in range(3):
    for j in range(3):
        print("*", end=" ")
    print()    # New line
```

Output:
```
* * * 
* * * 
* * * 
```

### Practical Example: Scan Multiple IPs

```python
ips = ["192.168.1.1", "192.168.1.2"]
ports = [22, 80, 443]

for ip in ips:
    for port in ports:
        print(f"Scanning {ip}:{port}")
```

Output:
```
Scanning 192.168.1.1:22
Scanning 192.168.1.1:80
Scanning 192.168.1.1:443
Scanning 192.168.1.2:22
Scanning 192.168.1.2:80
Scanning 192.168.1.2:443
```

---

## Practical Examples

### Example 1: Sum of Numbers

```python
total = 0

for i in range(1, 6):
    total += i

print(f"Sum: {total}")    # Sum: 15
```

### Example 2: Find Even Numbers

```python
for i in range(1, 11):
    if i % 2 == 0:
        print(f"{i} is even")
```

Output:
```
2 is even
4 is even
6 is even
8 is even
10 is even
```

### Example 3: Count Login Attempts

```python
attempts = 0
max_attempts = 3

while attempts < max_attempts:
    password = input("Enter password: ")
    
    if password == "secret123":
        print("Login successful!")
        break
    else:
        attempts += 1
        print(f"Wrong! {max_attempts - attempts} attempts left")

if attempts == max_attempts:
    print("Account locked!")
```

### Example 4: Simple Port List

```python
open_ports = []

for port in range(20, 26):
    open_ports.append(port)

print(f"Ports: {open_ports}")
# Ports: [20, 21, 22, 23, 24, 25]
```

---

## Common Mistakes

### Mistake 1: Forgetting to Update Counter

```python
# WRONG - Infinite loop!
count = 1
while count <= 5:
    print(count)
    # Forgot: count += 1

# CORRECT
count = 1
while count <= 5:
    print(count)
    count += 1
```

### Mistake 2: Wrong range() Values

```python
# WRONG - Doesn't include 5
for i in range(1, 5):
    print(i)    # Prints 1, 2, 3, 4

# CORRECT - Includes 5
for i in range(1, 6):
    print(i)    # Prints 1, 2, 3, 4, 5
```

### Mistake 3: Wrong Indentation

```python
# WRONG
for i in range(3):
print(i)    # Not indented!

# CORRECT
for i in range(3):
    print(i)    # Properly indented
```

---

## Quick Reference

### for Loop

```python
# Loop through list
for item in my_list:
    print(item)

# Loop with range
for i in range(5):
    print(i)
```

### while Loop

```python
# Basic while
while condition:
    # code
    
# With counter
count = 0
while count < 5:
    print(count)
    count += 1
```

### range() Function

```python
range(5)          # 0, 1, 2, 3, 4
range(1, 5)       # 1, 2, 3, 4
range(1, 10, 2)   # 1, 3, 5, 7, 9
```

---

## Summary

| Concept | Description |
|---------|-------------|
| `for` loop | Loop through items or range |
| `while` loop | Loop while condition is True |
| `range()` | Create sequence of numbers |
| Nested loop | Loop inside another loop |
| Infinite loop | Loop that never stops (`while True`) |

### Key Points

- `for` loop: know how many times
- `while` loop: until condition is False
- `range(5)` gives 0 to 4 (not 5!)
- Always update counter in `while` loop
- Use `Ctrl + C` to stop infinite loop
