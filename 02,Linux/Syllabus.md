# ✅ Linux Checklist for VAPT (Fresher)

##  Linux Basics
- [x] Linux directory structure (`/etc`, `/var`, `/home`, `/opt`, `/tmp`, `/root`)
- [x] Difference: root user vs normal user
- [x] File permissions basics (rwx)
- [x] Ownership concepts (user/group/others)
- [x] Hidden files (`.` prefix)

---

## File & Directory Commands
- [ ] `ls` (with `-la`)
- [ ] `cd`
- [ ] `pwd`
- [ ] `mkdir`
- [ ] `touch`
- [ ] `cp`
- [ ] `mv`
- [ ] `rm` (`-r`, `-f`)
- [ ] `cat`
- [ ] `less`
- [ ] `head`
- [ ] `tail`
- [ ] `find`
- [ ] `locate`
- [ ] `which`
- [ ] `whereis`

---

##  Text Processing (Super Important for VAPT)
- [ ] `grep` (`-i`, `-r`, `-n`)
- [ ] `cut`
- [ ] `awk` (basic)
- [ ] `sed` (basic)
- [ ] `sort`
- [ ] `uniq`
- [ ] `wc`
- [ ] `tr`
- [ ] pipes `|`
- [ ] redirection `>`, `>>`, `<`
- [ ] stderr redirection `2>/dev/null`

---

##  Users & Privileges
- [ ] `id`
- [ ] `whoami`
- [ ] `groups`
- [ ] `sudo` basics
- [ ] `/etc/passwd` meaning
- [ ] `/etc/shadow` meaning
- [ ] `su` vs `sudo`
- [ ] `useradd`, `usermod`, `passwd` (basic)

---

## Permissions (Must Know)
- [ ] Read/Write/Execute meaning for files vs directories
- [ ] Numeric permissions (777, 755, 644, 600)
- [ ] `chmod`
- [ ] `chown`
- [ ] `chgrp`
- [ ] SUID bit (`chmod u+s`)
- [ ] SGID bit
- [ ] Sticky bit (`/tmp` behavior)

---

## Processes & Services
- [ ] `ps aux`
- [ ] `top` / `htop`
- [ ] `kill` / `kill -9`
- [ ] `systemctl status/start/stop`
- [ ] `service` command (basic)
- [ ] Background jobs (`&`)
- [ ] `jobs`, `fg`, `bg`

---

## Package Management
### Debian/Ubuntu
- [ ] `apt update`
- [ ] `apt install`
- [ ] `dpkg -l`

### RedHat/CentOS
- [ ] `yum` / `dnf` basics
- [ ] `rpm -qa`

---

##  Networking in Linux (VAPT Must)
- [ ] `ip a`
- [ ] `ip r`
- [ ] `ifconfig` (legacy)
- [ ] `netstat` (legacy)
- [ ] `ss -tulnp`
- [ ] `ping`
- [ ] `traceroute`
- [ ] `nslookup`
- [ ] `dig`
- [ ] `curl`
- [ ] `wget`
- [ ] `arp -a`
- [ ] `route -n` (legacy)

---

##  Firewall Basics (Linux)
- [ ] `iptables` basics (high level)
- [ ] `ufw` basics
- [ ] `firewalld` basics

---

##  Important Files for Pentesting
- [ ] `/etc/passwd`
- [ ] `/etc/shadow`
- [ ] `/etc/sudoers`
- [ ] `/etc/hosts`
- [ ] `/etc/resolv.conf`
- [ ] `/etc/crontab`
- [ ] `/var/log/auth.log`
- [ ] `/var/log/syslog`
- [ ] `/var/log/secure` (RHEL)
- [ ] `/home/*/.ssh/authorized_keys`
- [ ] `/root/.ssh/`

---

##  Enumeration for VAPT / Pentesting
- [ ] Check current user + groups (`id`)
- [ ] Check sudo permissions (`sudo -l`)
- [ ] Check running services (`ps aux`, `systemctl`)
- [ ] Check open ports (`ss -tulnp`)
- [ ] Check cron jobs (`crontab -l`, `/etc/crontab`)
- [ ] Check writable directories (`find / -writable`)
- [ ] Check SUID binaries (`find / -perm -4000`)
- [ ] Check capabilities (`getcap -r /`)
- [ ] Check installed packages (`dpkg -l` / `rpm -qa`)
- [ ] Check kernel version (`uname -a`)

---

##  Logs & Monitoring (Basic)
- [ ] `journalctl`
- [ ] `dmesg`
- [ ] View logs using `cat/less/tail -f`

---

## SSH Basics
- [ ] SSH login (`ssh user@ip`)
- [ ] SSH key-based auth concept
- [ ] Private vs public key
- [ ] Permissions for keys (`chmod 600 id_rsa`)
- [ ] `~/.ssh/config` basics
- [ ] SSH port forwarding concept (basic)

---

##  Shell Basics (Very Important)
- [ ] Bash basics
- [ ] Environment variables (`export`, `$PATH`)
- [ ] `history`
- [ ] Tab completion
- [ ] Aliases (`alias`)
- [ ] `chmod +x script.sh`
- [ ] Running scripts (`./script.sh`)
- [ ] Shebang (`#!/bin/bash`)

---

## Bonus (Good for Interviews + Real Work)
- [ ] `tmux` basics
- [ ] `screen` basics
- [ ] `cron` scheduling basics
- [ ] `tar` and gzip (`tar -xvf`, `tar -czvf`)
- [ ] `zip` / `unzip`
- [ ] Basic bash scripting
