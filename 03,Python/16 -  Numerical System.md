

## What is a Numbering System?

A numbering system is a way to write numbers using symbols.

**Types we use in computers:**
- **Decimal** - What we use daily (0-9)
- **Binary** - What computers use (0-1)
- **Octal** - Shorthand for binary (0-7)
- **Hexadecimal** - Common in security (0-9, A-F)

---

## Types of Numbering Systems

| System | Base | Digits | Python Prefix |
|--------|------|--------|---------------|
| Decimal | 10 | 0-9 | None |
| Binary | 2 | 0, 1 | `0b` |
| Octal | 8 | 0-7 | `0o` |
| Hexadecimal | 16 | 0-9, A-F | `0x` |

---

## Decimal Number System

### What is Decimal?

- Base 10
- Uses: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
- Normal numbers we use daily

### Example

```python
a = 10
b = 255

print(a)    # 10
print(b)    # 255
```

---

## Binary Number System

### What is Binary?

- Base 2
- Uses only: 0 and 1
- Computers use this internally

### Binary in Python

Use `0b` prefix for binary.

```python
a = 0b101     # 5 in decimal
b = 0b1010    # 10 in decimal

print(a)    # 5
print(b)    # 10
```

### Convert Decimal to Binary

Use `bin()` function.

```python
print(bin(5))     # 0b101
print(bin(10))    # 0b1010
print(bin(255))   # 0b11111111
```

### Common Binary Values

| Decimal | Binary |
|---------|--------|
| 0 | 0b0 |
| 1 | 0b1 |
| 2 | 0b10 |
| 5 | 0b101 |
| 10 | 0b1010 |
| 255 | 0b11111111 |

---

## Octal Number System

### What is Octal?

- Base 8
- Uses: 0, 1, 2, 3, 4, 5, 6, 7
- Less common today

### Octal in Python

Use `0o` prefix for octal.

```python
a = 0o7      # 7 in decimal
b = 0o10     # 8 in decimal

print(a)    # 7
print(b)    # 8
```

### Convert Decimal to Octal

Use `oct()` function.

```python
print(oct(7))     # 0o7
print(oct(8))     # 0o10
print(oct(255))   # 0o377
```

### Common Octal Values

| Decimal | Octal |
|---------|-------|
| 7 | 0o7 |
| 8 | 0o10 |
| 10 | 0o12 |
| 255 | 0o377 |

---

## Hexadecimal Number System

### What is Hexadecimal?

- Base 16
- Uses: 0-9 and A-F
- Very common in security
- Used for: MAC addresses, colors, memory

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

Use `0x` prefix for hexadecimal.

```python
a = 0xA      # 10 in decimal
b = 0xF      # 15 in decimal
c = 0xFF     # 255 in decimal

print(a)    # 10
print(b)    # 15
print(c)    # 255
```

### Convert Decimal to Hexadecimal

Use `hex()` function.

```python
print(hex(10))    # 0xa
print(hex(15))    # 0xf
print(hex(255))   # 0xff
```

### Common Hex Values

| Decimal | Hex |
|---------|-----|
| 10 | 0xa |
| 15 | 0xf |
| 16 | 0x10 |
| 255 | 0xff |

---

## Conversion Functions

| Function | What it Does | Example |
|----------|--------------|---------|
| `bin()` | Decimal → Binary | `bin(10)` → `0b1010` |
| `oct()` | Decimal → Octal | `oct(10)` → `0o12` |
| `hex()` | Decimal → Hex | `hex(10)` → `0xa` |
| `int()` | Any → Decimal | `int('1010', 2)` → `10` |

### Example: Convert One Number

```python
num = 255

print(bin(num))    # 0b11111111
print(oct(num))    # 0o377
print(hex(num))    # 0xff
```

---

## Converting TO Decimal

### Binary to Decimal

```python
# Method 1: Use 0b prefix
num = 0b1010
print(num)    # 10

# Method 2: Use int()
num = int("1010", 2)
print(num)    # 10
```

### Octal to Decimal

```python
# Method 1: Use 0o prefix
num = 0o17
print(num)    # 15

# Method 2: Use int()
num = int("17", 8)
print(num)    # 15
```

### Hex to Decimal

```python
# Method 1: Use 0x prefix
num = 0xFF
print(num)    # 255

# Method 2: Use int()
num = int("FF", 16)
print(num)    # 255
```

---

## Simple Examples

### Example 1: Port Number

```python
port = 443

print(f"Decimal: {port}")
print(f"Binary: {bin(port)}")
print(f"Hex: {hex(port)}")
```

Output:
```
Decimal: 443
Binary: 0b110111011
Hex: 0x1bb
```

### Example 2: IP Octet

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

### Example 3: Hex to Decimal

```python
# MAC address part
hex_value = "FF"
decimal = int(hex_value, 16)

print(f"FF = {decimal}")    # FF = 255
```

---

## Why Important for Security?

| Use Case | Number System |
|----------|---------------|
| MAC Addresses | Hexadecimal |
| IP Addresses | Decimal |
| Memory Addresses | Hexadecimal |
| File Analysis | Hexadecimal |

---

## Quick Reference

### Prefixes

| System | Prefix | Example |
|--------|--------|---------|
| Binary | `0b` | `0b1010` |
| Octal | `0o` | `0o17` |
| Hex | `0x` | `0xFF` |

### Conversion

```python
# Decimal to others
bin(10)    # '0b1010'
oct(10)    # '0o12'
hex(10)    # '0xa'

# Others to decimal
int('1010', 2)    # 10 (binary)
int('12', 8)      # 10 (octal)
int('a', 16)      # 10 (hex)
```

---

## Summary

| System | Base | Prefix | Function |
|--------|------|--------|----------|
| Decimal | 10 | None | `int()` |
| Binary | 2 | `0b` | `bin()` |
| Octal | 8 | `0o` | `oct()` |
| Hex | 16 | `0x` | `hex()` |

### Key Points

- Decimal = normal numbers (0-9)
- Binary = computer language (0, 1)
- Hex = common in security (0-9, A-F)
- Use `bin()`, `oct()`, `hex()` to convert FROM decimal
- Use `int(string, base)` to convert TO decimal
