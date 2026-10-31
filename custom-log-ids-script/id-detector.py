import re
import time
import json
import requests
from collections import defaultdict
from datetime import datetime, timedelta


def follow(file_path):
    """Generator that mimics `tail -f`."""
    with open(file_path, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()


def parse_line(line):
    """Returns the source IP if the line is a failed login, else None."""
    pattern = r"Failed password for (invalid user )?\S+ from (?P<ip>[\d\.]+) port \d+"
    match = re.search(pattern, line)
    return match.group("ip") if match else None


# ---- إعدادات قابلة للتعديل ----
THRESHOLD = 10
TIME_WINDOW_MINUTES = 5

# ---- إعدادات Splunk HEC ----
HEC_URL = "https://inputs.prd-p-zq4l3.splunkcloud.com:443/services/collector/event"
HEC_TOKEN = "ضع-التوكن-بتاعك-هنا"

# ---- الذاكرة ----
attempts_by_ip = defaultdict(list)
alerted_ips = {}


def record_attempt(ip):
    """Records an attempt and returns current list of timestamps."""
    now = datetime.now()
    attempts_by_ip[ip].append(now)

    cutoff = now - timedelta(minutes=TIME_WINDOW_MINUTES)
    attempts_by_ip[ip] = [t for t in attempts_by_ip[ip] if t > cutoff]

    return attempts_by_ip[ip]


def build_alert(ip, timestamps):
    """Builds a structured JSON alert."""
    return {
        "alert_type": "ssh_bruteforce_detected",
        "source_ip": ip,
        "attempt_count": len(timestamps),
        "time_window_minutes": TIME_WINDOW_MINUTES,
        "first_attempt": timestamps[0].isoformat(),
        "last_attempt": timestamps[-1].isoformat(),
        "severity": "high",
        "detected_by": "custom_python_ids"
    }


def send_to_splunk(alert):
    """Sends the alert to Splunk via HEC."""
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    payload = {"event": alert, "sourcetype": "_json"}

    try:
        response = requests.post(HEC_URL, headers=headers, json=payload, timeout=5)
        if response.status_code == 200:
            print(f" Alert sent to Splunk for {alert['source_ip']}")
        else:
            print(f" Splunk returned status {response.status_code}: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f" Failed to send alert: {e}")


def should_alert(ip):
    """Prevents spamming the same alert repeatedly for the same IP."""
    last_alert_time = alerted_ips.get(ip)
    now = datetime.now()

    if last_alert_time is None or (now - last_alert_time) > timedelta(minutes=TIME_WINDOW_MINUTES):
        alerted_ips[ip] = now
        return True
    return False


if __name__ == "__main__":
    print(f"[*] Monitoring /var/log/auth.log for brute-force patterns...")
    print(f"[*] Threshold: {THRESHOLD} attempts / {TIME_WINDOW_MINUTES} minutes\n")

    for line in follow("/var/log/auth.log"):
        ip = parse_line(line)
        if ip:
            timestamps = record_attempt(ip)
            count = len(timestamps)
            print(f"[INFO] {ip} -> {count} failed attempts in last {TIME_WINDOW_MINUTES}min")

            if count >= THRESHOLD and should_alert(ip):
                alert = build_alert(ip, timestamps)
                print(f" [ALERT] Brute-force detected from {ip}!")
                print(json.dumps(alert, indent=2))
                send_to_splunk(alert)
