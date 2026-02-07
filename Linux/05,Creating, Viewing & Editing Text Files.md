# Redirect Output to a File or Program
### Output?
When you run a command, it shows results on screen. This is called output.

```bash
ls
```
Output appears on your screen.

## Two Types of Output





### Save Output to a File
#### Create New File or Overwrite (>)
```bash
ls > myfiles.txt
```
This saves the file list into myfiles.txt


```bash
echo "Hello" > greeting.txt
```

This creates a file with "Hello" inside.
**Warning: Using > will delete old content!**


#### Add to Existing File (>>)
```bash
echo "Line 1" > notes.txt       # Creates file
echo "Line 2" >> notes.txt      # Adds to file
echo "Line 3" >> notes.txt      # Adds more
```

Now notes.txt has 3 lines.


## Pipe ( | ) - Connect Commands

Send output of one command to another command.
```bash
cat /etc/passwd | grep root
```

**What happens:**
- cat /etc/passwd shows file content
- | sends that content to next command
- grep root finds lines with "root"

```bash
ls | head -5                    # Show first 5 files only
history | grep ssh              # Find ssh commands in history
cat /etc/passwd | wc -l         # Count total lines
```


