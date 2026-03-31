# 🛡️ Simulated Enterprise Cyber Range (Linux & Network Security)

## 📌 Overview

This project simulates a **real-world enterprise network environment** where attack and defense operations are performed on a secured Linux server. It focuses on **Linux security, network access control, and log monitoring**.

---

## 🎯 Objectives

* Build a secure Linux server environment
* Implement SSH hardening and access control
* Simulate cyber attacks (Red Team)
* Monitor and detect suspicious activity (Blue Team)

---

## 🧠 Architecture

```text
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
```

---

## 👥 Team Roles

### 🏢 Infrastructure Team

* Setup Ubuntu Server
* Configure SSH security
* Manage users and groups
* Apply firewall rules

---

### 🔴 Red Team

* Perform SSH brute-force attempts
* Scan open ports
* Attempt unauthorized access

---

### 🔵 Blue Team

* Monitor system logs
* Detect failed login attempts
* Analyze attack patterns

---

## 🔐 Security Implementations

* SSH key-based authentication
* Custom SSH port configuration
* Password login disabled
* Firewall rules using UFW / GUFW
* Role-based access control (users & groups)
* File permission and umask configuration

---

## 🛠️ Tools & Technologies

* Ubuntu Server
* Kali Linux
* UFW / GUFW
* OpenSSH
* Linux CLI

---

## 🧪 Attack Simulation

* SSH brute-force attempts
* Unauthorized login attempts
* Port scanning using Nmap

---

## 📊 Log Monitoring

* `/var/log/auth.log` → SSH login attempts
* Detection of failed and successful logins

---

## 📂 Project Structure

```bash
cyber-range-project/
│── README.md
│── setup/
│── user-management/
│── firewall/
│── attack-scenarios/
│── logs/
│── screenshots/
```

---

## 🚀 How to Run

1. Setup Ubuntu Server
2. Configure SSH and firewall
3. Connect using Kali Linux
4. Perform attack simulations
5. Monitor logs and analyze results

---

## 📸 Screenshots

(Add screenshots here)

---

## 🧾 Key Learnings

* Linux user and permission management
* Network access control using firewall
* Attack and defense fundamentals
* Log analysis and monitoring

---




