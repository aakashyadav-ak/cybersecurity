# Overview

This project simulates a real-world enterprise network environment where attack and defense operations are performed on a secured Linux server. It focuses on Linux security, network access control, and log monitoring.


# Objectives
- Build a secure Linux server environment
- Implement SSH hardening and access control
- Simulate cyber attacks (Red Team)
- Monitor and detect suspicious activity (Blue Team)


#  Architecture

Kali Linux (Attacker)
        │
        ▼
Firewall (UFW / GUFW)
        │
        ▼
Ubuntu Server (Target)
        │
        ▼
Logs (/var/log/auth.log)
        │
        ▼
Blue Team Analysis



# Infrastructure
- Setup Ubuntu Server
- Configure SSH security
- Manage users and groups
- Apply firewall rules

# Red Team
- Perform SSH brute-force attempts
- Scan open ports
- Attempt unauthorized access

# Blue Team
- Monitor system logs
- Detect failed login attempts
- Analyze attack patterns


# Security Implementations
- SSH key-based authentication
- Custom SSH port configuration
- Password login disabled
- Firewall rules using UFW / GUFW
- Role-based access control (users & groups)
- File permission and umask configuration


# Tools & Technologies
- Ubuntu Server
- Kali Linux
- UFW / GUFW
- OpenSSH
- Linux CLI


# Attack Simulation
- SSH brute-force attempts
- Unauthorized login attempts
- Port scanning using Nmap

# Log Monitoring
- /var/log/auth.log → SSH login attempts
- Detection of failed and successful logins