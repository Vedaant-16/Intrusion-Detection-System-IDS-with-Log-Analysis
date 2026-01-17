# 🔐 Intrusion Detection System (IDS) with Log Correlation & SOC Dashboard

## 📌 Overview
This project implements a **Host-Based Intrusion Detection System (HIDS)** that analyzes operating system logs and database logs to detect suspicious and malicious activities. The IDS uses **rule-based log analysis** and **time-window event correlation** to identify high-confidence intrusion events and presents them through a **SOC-style web dashboard**.

The system is designed for **educational and demonstration purposes**, closely reflecting real-world security monitoring and SOC workflows.

---

## 🚀 Features
- SSH brute-force attack detection using authentication logs
- Unauthorized privilege escalation detection (sudo misuse)
- Suspicious malware execution detection based on process paths
- Destructive database query detection (DROP, DELETE, TRUNCATE)
- Correlation of OS-level and database-level events
- Severity-based alert classification
- SOC-style dashboard with filters, timeline, and auto-refresh


## 🏗️ System Architecture
OS & DB Logs
↓
Python IDS Engine
↓
JSON Alert Store
↓
Flask REST API
↓
SOC Web Dashboard


## 🧪 Technologies Used
- **Backend:** Python
- **Web Framework:** Flask
- **Frontend:** HTML, CSS, JavaScript
- **Log Analysis:** Regex-based parsing
- **Data Storage:** JSON
- **Platform:** Linux (Kali / Ubuntu)
- 
## 📂 Project Structure
ids_project/
├── ids_log_correlation.py # IDS detection and correlation engine
├── app.py # Flask backend server
├── alerts.json # Generated alert data
├── templates/
│ └── index.html # Dashboard UI
├── static/
│ ├── style.css # Dashboard styling
│ └── script.js # Dashboard logic
├── auth.log.sample # Sample OS logs
└── mysql.log.sample # Sample database logs

## ▶️ How to Run
### 1️⃣ Run the IDS engine
python3 ids_log_correlation.py
2️⃣ Start the dashboard server
python3 app.py
3️⃣ Open the dashboard
http://127.0.0.1:5000

📈 Future Enhancements
Real-time log monitoring

Automatic IP blocking using iptables

MITRE ATT&CK technique mapping

SIEM integration (Elastic Stack)

Analyst acknowledgment and incident workflow
