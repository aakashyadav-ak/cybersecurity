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