# 1: Linux Log Files Basics

## Critical Linux Log Files

| Log File              | What It Contains        | Distro          |
|-----------------------|-------------------------|-----------------|
| /var/log/auth.log     | Authentication logs     | Ubuntu/Debian   |
| /var/log/secure       | Authentication logs     | RHEL/CentOS     |
| /var/log/syslog       | System messages         | Ubuntu/Debian   |
| /var/log/messages     | System messages         | RHEL/CentOS     |
| /var/log/cron         | Cron job logs           | All             |
| /var/log/apache2/     | Web server logs         | Apache          |
| /var/log/nginx/       | Web server logs         | Nginx           |

### /var/log/auth.log (Authentication)

**What's Logged Here:**
- ✅ SSH logins (success/fail)
- ✅ sudo usage
- ✅ su (switch user)
- ✅ User creation/deletion
- ✅ Password changes
- ✅ PAM authentication events