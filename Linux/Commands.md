| Category | Command | Use | Example |
|----------|---------|-----|---------|
| Navigation | `pwd` | Show current directory path | `pwd` |
| Navigation | `ls` | List files/folders | `ls -la` |
| Navigation | `cd` | Change directory | `cd /var/log` |
| Navigation | `mkdir` | Create folder | `mkdir -p recon/nmap/scans` |
| Files | `touch` | Create empty file | `touch notes.txt` |
| Files | `cat` | View file content | `cat notes.txt` |
| Files | `less` | View large file (scroll) | `less /etc/passwd` |
| Files | `head` | Show first lines | `head -n 20 scan.txt` |
| Files | `tail` | Show last lines | `tail -n 20 scan.txt` |
| Files | `tail -f` | Live log monitoring | `tail -f /var/log/auth.log` |
| Search | `grep` | Search inside files | `grep -Ri "password" .` |
| Search | `find` | Find files by name | `find /var/www -name "*.php"` |
| Search | `which` | Locate tool path | `which nmap` |
| Search | `locate` | Fast file search (DB based) | `locate id_rsa` |
| Copy/Move | `cp` | Copy files/folders | `cp scan.txt backup.txt` |
| Copy/Move | `cp -r` | Copy folders | `cp -r loot loot_backup` |
| Copy/Move | `mv` | Move/rename | `mv report.txt final_report.txt` |
| Delete | `rm` | Delete file | `rm temp.txt` |
| Delete | `rm -r` | Delete folder | `rm -r testfolder` |
| Permissions | `whoami` | Show current user | `whoami` |
| Permissions | `id` | Show user + groups | `id` |
| Permissions | `sudo -i` | Switch to root | `sudo -i` |
| Permissions | `chmod` | Change permissions | `chmod +x exploit.sh` |
| Permissions | `chown` | Change owner | `sudo chown ak:ak report.txt` |
| Output | `>` | Overwrite output to file | `nmap 10.0.0.1 > nmap.txt` |
| Output | `>>` | Append output to file | `echo "done" >> notes.txt` |
| Output | `|` | Pipe output to another command | `cat nmap.txt \| grep open` |
| Networking | `ip a` | Show IP address | `ip a` |
| Networking | `ping` | Check connectivity | `ping -c 4 8.8.8.8` |
| Networking | `curl` | Send web request | `curl -I https://example.com` |
| Networking | `wget` | Download file | `wget http://site.com/file.zip` |
| Networking | `ssh` | Remote login | `ssh user@192.168.1.10` |
| Processes | `ps aux` | Show running processes | `ps aux` |
| Processes | `top` | Live system usage | `top` |
| Processes | `kill` | Kill process | `kill -9 1234` |
| System | `uname -a` | Kernel/system info | `uname -a` |
| System | `df -h` | Disk usage | `df -h` |
| System | `du -sh` | Folder size | `du -sh loot/` |
| Archives | `tar` | Extract tar files | `tar -xvzf tools.tar.gz` |
| Archives | `unzip` | Extract zip | `unzip file.zip` |
| History | `history` | Show command history | `history` |
| History | `!!` | Repeat last command | `!!` |
| History | `!number` | Run history command by number | `!55` |
