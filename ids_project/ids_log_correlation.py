import re
import json
import os
from datetime import datetime

# ================= CONFIG =================

OS_LOG_FILE = "auth.log.sample"
DB_LOG_FILE = "mysql.log.sample"
ALERT_FILE = "alerts.json"

FAILED_LOGIN_THRESHOLD = 3
CORRELATION_WINDOW_SECONDS = 120
ADMIN_USERS = ["root"]

# ================= REGEX PATTERNS =================

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
)

SUDO_PATTERN = re.compile(
    r"sudo:\s+(\w+)\s+.*COMMAND="
)

DB_DANGEROUS_QUERY = re.compile(
    r"(DROP|DELETE|TRUNCATE)\s+TABLE",
    re.IGNORECASE
)

MALWARE_PATH_PATTERN = re.compile(
    r"/tmp/|/dev/shm/|\.xmr"
)

# ================= UTILS =================

def read_file(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return f.readlines()

def save_alerts(alerts):
    if not alerts:
        return

    existing = []
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            existing = json.load(f)

    existing.extend(alerts)

    with open(ALERT_FILE, "w") as f:
        json.dump(existing, f, indent=4)

# ================= DETECTION =================

def detect_bruteforce(logs):
    ip_count = {}
    alerts = []

    for line in logs:
        match = FAILED_LOGIN_PATTERN.search(line)
        if match:
            ip = match.group(1)
            ip_count[ip] = ip_count.get(ip, 0) + 1

            if ip_count[ip] == FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "type": "Brute Force Attack",
                    "ip": ip,
                    "timestamp": datetime.now().isoformat()
                })
    return alerts

def detect_privilege_escalation(logs):
    alerts = []

    for line in logs:
        match = SUDO_PATTERN.search(line)
        if match:
            user = match.group(1)
            if user not in ADMIN_USERS:
                alerts.append({
                    "type": "Privilege Escalation",
                    "user": user,
                    "log": line.strip(),
                    "timestamp": datetime.now().isoformat()
                })
    return alerts

def detect_malware(logs):
    alerts = []

    for line in logs:
        if MALWARE_PATH_PATTERN.search(line):
            alerts.append({
                "type": "Possible Malware Execution",
                "log": line.strip(),
                "timestamp": datetime.now().isoformat()
            })
    return alerts

def detect_db_attack(db_logs):
    alerts = []

    for line in db_logs:
        if DB_DANGEROUS_QUERY.search(line):
            alerts.append({
                "type": "Database Destructive Query",
                "query": line.strip(),
                "timestamp": datetime.now().isoformat()
            })
    return alerts

# ================= CORRELATION =================

def correlate_events(os_alerts, db_alerts):
    correlated = []

    for os_event in os_alerts:
        os_time = datetime.fromisoformat(os_event["timestamp"])

        for db_event in db_alerts:
            db_time = datetime.fromisoformat(db_event["timestamp"])

            delta = abs((db_time - os_time).seconds)

            if delta <= CORRELATION_WINDOW_SECONDS:
                correlated.append({
                    "type": "Correlated Intrusion",
                    "confidence": "HIGH",
                    "os_event": os_event,
                    "db_event": db_event
                })

    return correlated

# ================= MAIN =================

def main():
    os_logs = read_file(OS_LOG_FILE)
    db_logs = read_file(DB_LOG_FILE)

    os_alerts = []
    os_alerts.extend(detect_bruteforce(os_logs))
    os_alerts.extend(detect_privilege_escalation(os_logs))
    os_alerts.extend(detect_malware(os_logs))

    db_alerts = detect_db_attack(db_logs)

    correlated_alerts = correlate_events(os_alerts, db_alerts)

    all_alerts = os_alerts + db_alerts + correlated_alerts

    save_alerts(all_alerts)

    if all_alerts:
        print("\n[!] INTRUSION DETECTED\n")
        for alert in all_alerts:
            print(json.dumps(alert, indent=2))
    else:
        print("\n[✓] System clean — no intrusion detected\n")

if __name__ == "__main__":
    main()

