
```
┌─────────────────────────────────────────────────────────────────┐
│                    WHAT ARE COMMENTS?                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Comments are notes written in code that Python IGNORES.        │
│                                                                  │
│   • They are for HUMANS, not for the computer                    │
│   • Python skips them during execution                           │
│   • They don't affect how the program runs                       │
│                                                                  │
│   Purpose:                                                       │
│   ✓ Explain what the code does                                  │
│   ✓ Make code easier to understand                              │
│   ✓ Leave notes for yourself or others                          │
│   ✓ Temporarily disable code for testing                        │
│   ✓ Document functions and programs                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

# Single-line Comments
```python
# Example 1: Comment on its own line
# This program prints a greeting
print("Hello, World!")

# Example 2: Comment at end of line (inline comment)
print("Hello")  # Display greeting message

# Example 3: Multiple single-line comments
# This is line 1 of the comment
# This is line 2 of the comment
# This is line 3 of the comment
print("Python")

# Example 4: Commenting out code (disabling it temporarily)
print("This will run")
# print("This will NOT run - it's commented out")
print("This will also run")
```


# Multi-line Comments (Docstrings)
## Using Triple Quotes

```python
"""
This is a multi-line comment.
It can span across multiple lines.
Very useful for longer explanations.
"""

'''
You can also use single quotes.
This works exactly the same way.
Choose one style and be consistent.
'''
```

### Docstrings in Functions
```python
def calculate_area(length, width):
    """
    Calculate the area of a rectangle.
    
    Parameters:
        length: The length of the rectangle
        width: The width of the rectangle
    
    Returns:
        The area (length × width)
    """
    return length * width


# Access the docstring
print(calculate_area.__doc__)

# Or use help()
help(calculate_area)
```

**Output**
```
    Calculate the area of a rectangle.
    
    Parameters:
        length: The length of the rectangle
        width: The width of the rectangle
    
    Returns:
        The area (length × width)
```