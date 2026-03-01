```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT IS USER INPUT?                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   User Input allows your program to receive data from the user  │
│   while the program is running.                                  │
│                                                                  │
│   Instead of hardcoding values:                                  │
│       name = "Alice"                                             │
│                                                                  │
│   You can ask the user:                                          │
│       name = input("Enter your name: ")                          │
│                                                                  │
│   This makes programs:                                           │
│   • Interactive                                                  │
│   • Dynamic                                                      │
│   • More useful                                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## The input() Function
```
┌─────────────────────────────────────────────────────────────────┐
│                    input() FUNCTION                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Syntax: input(prompt)                                          │
│                                                                  │
│   • Displays the prompt message                                  │
│   • Waits for user to type something                            │
│   • User presses Enter                                          │
│   • Returns what user typed as a STRING                         │
│                                                                  │
│   ⚠️ IMPORTANT: input() ALWAYS returns a STRING!                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```


**example:**
```bash
# Basic input
name = input("Enter your name: ")
print(f"Hello, {name}!")

# What happens:
# 1. "Enter your name: " is displayed
# 2. Program waits for user to type
# 3. User types "Alice" and presses Enter
# 4. "Alice" is stored in 'name' variable
# 5. "Hello, Alice!" is printed
```


### Input Always Returns String!
==VERY IMPORTANT: input() ALWAYS returns a STRING!==
```
# VERY IMPORTANT: input() ALWAYS returns a STRING!

age = input("Enter your age: ")
print(age)              # "25" (looks like a number)
print(type(age))        # <class 'str'> (but it's a string!)

# This causes problems with math:
# age + 1               # ERROR! Can't add string + int

# User types: 25
# Variable contains: "25" (string, not integer)
```


## String Input
**Basic String Input:**
```bash
# Strings are the natural type for input()
# No conversion needed

name = input("Enter your name: ")
print(f"Hello, {name}!")
print(type(name))    # <class 'str'>

# Multiple string inputs
first_name = input("Enter first name: ")
last_name = input("Enter last name: ")
full_name = first_name + " " + last_name
print(f"Full name: {full_name}")
```



## Integer Input

#### Converting String to Integer
```bash
# input() returns string, so we must convert

# WRONG way:
age = input("Enter your age: ")
# age is a string like "25"

# RIGHT way:
age = int(input("Enter your age: "))
# Now age is an integer: 25

print(f"Next year you'll be {age + 1}")
print(type(age))    # <class 'int'>
```

```bash
# Two ways to convert

# Method 1: All in one line
age = int(input("Enter your age: "))

# Method 2: Separate steps (clearer)
age_string = input("Enter your age: ")    # "25"
age = int(age_string)                      # 25

# Both methods work the same
```


## Float Input
#### Converting String to Float
```bash
# For decimal numbers, use float()

# Get float input
price = float(input("Enter price: "))
print(f"Price: ${price}")
print(type(price))    # <class 'float'>

# Calculations
tax_rate = 0.08
total = price + (price * tax_rate)
print(f"Total with tax: ${total:.2f}")
```