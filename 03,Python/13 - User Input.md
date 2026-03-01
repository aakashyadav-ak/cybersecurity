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