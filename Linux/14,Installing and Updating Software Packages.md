## Kali Linux Package Management
Since you use Kali Linux (Debian-based), you need APT instead of DNF/RPM.


##  Install and Update Software Packages
APT Package Manager
APT = Advanced Package Tool

Main command: apt

### Update Package Lists
**Always do this first!**
```
sudo apt update
```

This downloads the latest package information from repositories.

Note: This does NOT install updates. Just refreshes the list.

### Upgrade Installed Packages
**Upgrade all packages:**
```
sudo apt upgrade
```

**Upgrade + remove old packages:**
```
sudo apt full-upgrade
```

**Update + Upgrade together:**
```
sudo apt update && sudo apt upgrade -y
```


#### Search for Packages
```
apt search nmap
```

#### Get Package Information
```
apt show nmap
```

**output:**
```
Package: nmap
Version: 7.93+dfsg1-1
Priority: optional
Section: net
Maintainer: Debian...
Installed-Size: 24.5 MB
Depends: libc6, liblinear4...
Description: The Network Mapper
```


### Install Package
```
sudo apt install nmap
```

**Install multiple packages:**
```
sudo apt install nmap vim curl wget
```

**Install without confirmation:**
```
sudo apt install -y nmap
```


#### Remove Package
**Remove package (keep config files):**
```
sudo apt remove nmap
```

**Remove package + config files:**
```
sudo apt purge nmap
```


### List Packages
**List installed packages:**
```
apt list --installed
```