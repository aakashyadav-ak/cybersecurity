
# Module 19: Numbering System

## What is a Numbering System?

A numbering system is a way to represent numbers using symbols.

We use different numbering systems in computers:
- **Decimal** - What humans use (0-9)
- **Binary** - What computers use (0-1)
- **Octal** - Shorthand for binary (0-7)
- **Hexadecimal** - Shorthand for binary (0-9, A-F)

---

## Types of Numbering Systems

| System | Base | Digits Used | Prefix in Python |
|--------|------|-------------|------------------|
| Decimal | 10 | 0-9 | None |
| Binary | 2 | 0, 1 | `0b` |
| Octal | 8 | 0-7 | `0o` |
| Hexadecimal | 16 | 0-9, A-F | `0x` |

---

## 1. Decimal Number System

### What is Decimal?

- Base 10 system
- Uses digits: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
- The system we use daily
- Default number system in Python

### Examples

```python
a = 10
b = 255
c = 1000

print(a)    # 10
print(b)    # 255
print(c)    # 1000
```

---

## 2. Binary Number System

### What is Binary?

- Base 2 system
- Uses only: 0 and 1
- Computers use binary internally
- Each digit is called a "bit"

### Binary in Python

Use prefix `0b` to write binary numbers.

```python
a = 0b101      # 5 in decimal
b = 0b1010     # 10 in decimal
c = 0b11111111 # 255 in decimal

print(a)    # 5
print(b)    # 10
print(c)    # 255
```

### Convert Decimal to Binary

Use `bin()` function.

```python
print(bin(5))      # 0b101
print(bin(10))     # 0b1010
print(bin(255))    # 0b11111111
```

### Understanding Binary

```
Binary:  1    0    1    0
         ↓    ↓    ↓    ↓
Power:   2³   2²   2¹   2⁰
Value:   8    4    2    1

Calculation: 8 + 0 + 2 + 0 = 10
So: 1010 in binary = 10 in decimal
```

### Common Binary Values

| Decimal | Binary |
|---------|--------|
| 0 | 0b0 |
| 1 | 0b1 |
| 2 | 0b10 |
| 3 | 0b11 |
| 4 | 0b100 |
| 5 | 0b101 |
| 8 | 0b1000 |
| 10 | 0b1010 |
| 16 | 0b10000 |
| 255 | 0b11111111 |

---

## 3. Octal Number System

### What is Octal?

- Base 8 system
- Uses digits: 0, 1, 2, 3, 4, 5, 6, 7
- Shorter way to write binary
- Less common today

### Octal in Python

Use prefix `0o` to write octal numbers.

```python
a = 0o7       # 7 in decimal
b = 0o10      # 8 in decimal
c = 0o17      # 15 in decimal
d = 0o377     # 255 in decimal

print(a)    # 7
print(b)    # 8
print(c)    # 15
print(d)    # 255
```

### Convert Decimal to Octal

Use `oct()` function.

```python
print(oct(7))      # 0o7
print(oct(8))      # 0o10
print(oct(15))     # 0o17
print(oct(255))    # 0o377
```

### Common Octal Values

| Decimal | Octal |
|---------|-------|
| 0 | 0o0 |
| 7 | 0o7 |
| 8 | 0o10 |
| 10 | 0o12 |
| 15 | 0o17 |
| 16 | 0o20 |
| 64 | 0o100 |
| 255 | 0o377 |

---

## Hexadecimal Number System

### What is Hexadecimal?

- Base 16 system
- Uses: 0-9 and A-F
- Very common in computing
- Used for colors, memory addresses, MAC addresses

### Hex Digits

| Decimal | Hex |
|---------|-----|
| 0-9 | 0-9 |
| 10 | A |
| 11 | B |
| 12 | C |
| 13 | D |
| 14 | E |
| 15 | F |

### Hexadecimal in Python

Use prefix `0x` to write hexadecimal numbers.

```python
a = 0xA       # 10 in decimal
b = 0xF       # 15 in decimal
c = 0x10      # 16 in decimal
d = 0xFF      # 255 in decimal

print(a)    # 10
print(b)    # 15
print(c)    # 16
print(d)    # 255
```

### Convert Decimal to Hexadecimal

Use `hex()` function.

```python
print(hex(10))     # 0xa
print(hex(15))     # 0xf
print(hex(16))     # 0x10
print(hex(255))    # 0xff
```

### Common Hex Values

| Decimal | Hexadecimal |
|---------|-------------|
| 0 | 0x0 |
| 10 | 0xa |
| 15 | 0xf |
| 16 | 0x10 |
| 100 | 0x64 |
| 255 | 0xff |
| 256 | 0x100 |

---

## Conversion Functions

| Function | What it Does | Example |
|----------|--------------|---------|
| `bin()` | Decimal to Binary | `bin(10)` → `0b1010` |
| `oct()` | Decimal to Octal | `oct(10)` → `0o12` |
| `hex()` | Decimal to Hex | `hex(10)` → `0xa` |
| `int()` | Any to Decimal | `int('1010', 2)` → `10` |

### Example

```python
number = 255

print(f"Decimal: {number}")
print(f"Binary: {bin(number)}")
print(f"Octal: {oct(number)}")
print(f"Hex: {hex(number)}")
```

Output:
```
Decimal: 255
Binary: 0b11111111
Octal: 0o377
Hex: 0xff
```

---

## Converting TO Decimal

### Binary to Decimal

```python
# Method 1: Use 0b prefix
num = 0b1010
print(num)    # 10

# Method 2: Use int() with base 2
num = int("1010", 2)
print(num)    # 10
```

### Octal to Decimal

```python
# Method 1: Use 0o prefix
num = 0o17
print(num)    # 15

# Method 2: Use int() with base 8
num = int("17", 8)
print(num)    # 15
```

### Hex to Decimal

```python
# Method 1: Use 0x prefix
num = 0xFF
print(num)    # 255

# Method 2: Use int() with base 16
num = int("FF", 16)
print(num)    # 255
```

---

## Practical Examples

### Example 1: IP Address Octet

```python
octet = 192

print(f"Decimal: {octet}")
print(f"Binary: {bin(octet)}")
print(f"Hex: {hex(octet)}")
```

Output:
```
Decimal: 192
Binary: 0b11000000
Hex: 0xc0
```

### Example 2: Port Number

```python
port = 443

print(f"Port {port}")
print(f"Binary: {bin(port)}")
print(f"Hex: {hex(port)}")
```

Output:
```
Port 443
Binary: 0b110111011
Hex: 0x1bb
```

### Example 3: MAC Address Part

```python
part = "FF"
decimal_value = int(part, 16)
print(f"FF in decimal: {decimal_value}")    # 255
```

---

## Security Uses

| Use Case | Number System |
|----------|---------------|
| MAC Addresses | Hexadecimal |
| IP Addresses | Decimal / Binary |
| Memory Addresses | Hexadecimal |
| File Signatures | Hexadecimal |
| Subnet Masks | Binary |

---

## Quick Reference

### Prefixes

| System | Prefix | Example |
|--------|--------|---------|
| Binary | `0b` | `0b1010` |
| Octal | `0o` | `0o17` |
| Hexadecimal | `0x` | `0xFF` |

### Conversion Functions

```python
# Decimal to other systems
bin(10)          # '0b1010'
oct(10)          # '0o12'
hex(10)          # '0xa'

# Other systems to decimal
int('1010', 2)   # 10 (binary)
int('12', 8)     # 10 (octal)
int('a', 16)     # 10 (hex)

# Direct notation
0b1010           # 10
0o12             # 10
0xa              # 10
```

---

## Summary

| System | Base | Digits | Prefix | Function |
|--------|------|--------|--------|----------|
| Decimal | 10 | 0-9 | None | `int()` |
| Binary | 2 | 0-1 | `0b` | `bin()` |
| Octal | 8 | 0-7 | `0o` | `oct()` |
| Hexadecimal | 16 | 0-9, A-F | `0x` | `hex()` |

### Key Points

- Computers use binary (0 and 1)
- Hexadecimal is common in security
- Use `bin()`, `oct()`, `hex()` to convert FROM decimal
- Use `int(string, base)` to convert TO decimal
- Prefixes: `0b` (binary), `0o` (octal), `0x` (hex)

---

