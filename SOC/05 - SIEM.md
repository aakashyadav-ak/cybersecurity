## 1: SIEM Fundamentals
**SIEM** = Security Information and Event Management

==SIEM collects logs from multiple sources, normalizes them into a standard format, correlates events to detect threats, and alerts analysts. It's the central nervous system of a SOC.==

```
SIEM Pipeline:

LOG COLLECTION → NORMALIZATION → CORRELATION → ALERTING → DASHBOARD
     │                │               │             │           │
   Gather         Standardize      Find          Notify      Visualize
   all logs        format         patterns       analysts
```

### Key SIEM Concepts:

## SIEM / Log Analysis Basic Concepts

| Concept       | Meaning                           | Example                          |
|--------------|------------------------------------|----------------------------------|
| Log Source   | Where logs come from               | Windows, Firewall, Linux         |
| Index        | Storage container for logs         | "windows_logs", "firewall"       |
| Event        | Single log entry                   | One failed login                 |
| Field        | Data element in event              | EventID, Username, IP            |
| Query        | Search command                     | Find all failed logins           |
| Alert        | Automated notification             | Trigger when >10 failures        |
| Correlation  | Connect related events             | Failed logins → then success     |

### 

### Popular SIEMs Platforms & Query Languages

| SIEM                  | Query Language   | Common In                     |
|-----------------------|------------------|-------------------------------|
| Splunk                | SPL              | Enterprise, MSSPs             |
| Microsoft Sentinel    | KQL              | Cloud/Azure environments      |
| Elastic SIEM          | Lucene / EQL     | Open-source environments      |
| IBM QRadar            | AQL              | Large enterprises             |
| Chronicle (Google)    | YARA-L           | Google Cloud                  |

____

# 2: Splunk SPL Basics

**SPL** = Search Processing Language

### Basic Query Structure:
```
index=<index_name> <search_terms>
| command1
| command2
| command3
```

### Essential SPL Commands:
#### 1. Basic Search
```
# Search all Windows events
index=windows

# Search for specific EventID
index=windows EventID=4625

# Search with multiple conditions
index=windows EventID=4625 src_ip="45.142.212.61"

# Search with wildcard
index=windows user=admin*

# Search with time range
index=windows EventID=4625 earliest=-24h latest=now
```


#### 2. stats count by

**Purpose:** Count events grouped by field
```
# Count failed logins by source IP
index=windows EventID=4625
| stats count by src_ip

# Output:
# src_ip          | count
# 45.142.212.61   | 523
# 192.168.1.50    | 12
# 10.0.0.5        | 3

# Count failed logins by username
index=windows EventID=4625
| stats count by user

# Count by multiple fields
index=windows EventID=4625
| stats count by src_ip, user
```


#### 3. table

**Purpose:** Display specific fields only
```
# Show only these columns
index=windows EventID=4625
| table _time, src_ip, user, dest

# Output:
# _time               | src_ip        | user  | dest
# 2024-03-15 10:23:45 | 45.142.212.61 | admin | DC01
# 2024-03-15 10:23:46 | 45.142.212.61 | admin | DC01
```

#### 4. sort

**Purpose:** Order results
```
# Sort by count (descending = highest first)
index=windows EventID=4625
| stats count by src_ip
| sort -count

# Sort ascending (lowest first)
index=windows EventID=4625
| stats count by src_ip
| sort +count

# Sort by time
index=windows EventID=4625
| sort -_time
| table _time, src_ip, user
```


____

# 3: KQL Basics (Microsoft Sentinel)




____

# 4: Detection Queries
## Brute Force Detection

**Splunk:**
```
index=windows EventID=4625
| stats count by src_ip
| where count > 50
| sort -count
```

##  Password Spraying Detection
**Splunk:**
```
index=windows EventID=4625
| stats dc(user) as unique_users, count by src_ip
| where unique_users > 10
```

## Successful Login After Failures
**Splunk:**
```
index=windows (EventID=4625 OR EventID=4624)
| stats count(eval(EventID=4625)) as failures, count(eval(EventID=4624)) as successes by src_ip
| where failures > 10 AND successes > 0
```

## Suspicious PowerShell Detection
**Splunk:**
```
index=windows EventID=4104
| search ScriptBlockText="*DownloadString*" OR ScriptBlockText="*-enc*" OR ScriptBlockText="*IEX*"
| table _time, ComputerName, ScriptBlockText
```

##  New Admin Account Created
**Splunk:**
```
index=windows EventID=4720
| join user [search index=windows EventID=4732 group_name="Administrators"]
| table _time, user, src_user
```

##  Log Clearing Detection
**Splunk:**
```
index=windows EventID=1102
| table _time, user, ComputerName
```