# Validate Network Configuration
### Check IP Address

**Show all interfaces:**
```
ip a
```

```
ifconfig
```

### Check Routing Table
```
ip route
```

### Check DNS Configuration
```
cat /etc/resolv.conf
```

### Test Network Connectivity

ping - Test if Host is Reachable
```
ping 192.168.1.1
```

```
ping -c 4 192.168.1.1
```
Sends 4 pings only.


### Test DNS Resolution
```
nslookup google.com
```

```
dig google.com
```

#### traceroute - Show Path to Destination
```
traceroute google.com
```
Shows each hop (router) along the way.

