
# Service/Daemon


**Service=**       Program that runs in background
**Daemon=**	Same thing! (Background service)

**Examples:**
- sshd - SSH server (lets you connect remotely)
- httpd - Apache web server
- nginx - Nginx web server
- mysqld - MySQL database
- crond - Scheduled tasks
- firewalld - Firewall
Note: Many daemon names end with d (for daemon).


#### Service vs Regular Process

| Feature        | Regular Process       | Service/Daemon       |
| :------------- | :-------------------- | :------------------- |
| **Startup**    | You start it          | Starts automatically |
| **Visibility** | Runs in foreground    | Runs in background   |
| **Lifespan**   | Stops when you logout | Keeps running        |
| **Terminal**   | Has a terminal (TTY)  | No terminal (`?`)    |



## Identify Automatically Started System Processes
### systemd?
systemd is the system manager in RHEL.

**It controls:**
- Starting/stopping services
- Boot process
- System logging
- And much more


#### List All Services

**All services:**
```
systemctl list-units --type=service
```


___ 

# Control System Services