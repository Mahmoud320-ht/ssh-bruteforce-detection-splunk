# Custom Log-Based Intrusion Detection Script

Part of the [`soc-projects`](https://github.com/Mahmoud320-ht/soc-projects) repository.

A custom Python intrusion detection script that monitors Linux authentication logs in real time, detects SSH brute-force patterns using a sliding time-window algorithm, and forwards structured JSON alerts directly to Splunk via the HTTP Event Collector (HEC) — without relying on Splunk's own SPL detection logic.

## Overview
auth.log → Python monitor (tail -f style) → Parse & track attempts per IP → Sliding window threshold check → JSON alert → Splunk HEC


Unlike the earlier Splunk-based detection projects in this repository, where Splunk's SPL engine performs the pattern matching, this project moves the detection logic into custom code. Splunk here only receives pre-built, structured alerts — the kind of lightweight detection + SIEM integration pattern commonly used by security automation and detection engineering teams.

## Why This Project Is Different

| | SPL-based detection (previous projects) | This project |
|---|---|---|
| Who detects the pattern? | Splunk (via SPL query) | The Python script itself |
| Splunk's role | Full analysis engine | Receives ready-made structured alerts |
| Core skill demonstrated | SPL fluency | Detection logic implementation + system integration |

## Lab Architecture

| Machine | Role | Purpose |
|---|---|---|
| Kali Linux | Attacker | Generates brute-force traffic (Hydra) |
| Ubuntu Server | Victim | Runs the detection script against its own `auth.log` |
| Splunk Cloud | SIEM | Receives structured alerts via HEC, no parsing required |

All machines were virtual machines running on an isolated network, owned and controlled by the author.

## Tools Used

- **Python 3** (`re`, `requests`, `collections.defaultdict`, `datetime`) — detection logic and HEC integration
- **Hydra** — SSH brute-force traffic generation for testing
- **Splunk Cloud HTTP Event Collector (HEC)** — structured alert ingestion

## How It Works

### 1. Real-Time Log Monitoring
The script follows `/var/log/auth.log` the way `tail -f` does, using a Python generator that seeks to the end of the file and yields new lines as they're written — without re-reading historical data on each run.

### 2. Parsing Failed Login Attempts
Each new line is checked against a regex pattern matching SSH failed-password events, extracting the source IP:
```python
pattern = r"Failed password for (invalid user )?\S+ from (?P<ip>[\d\.]+) port \d+"
```

### 3. Sliding Window Threshold Detection
Every failed attempt is timestamped and stored per source IP. On each new attempt, timestamps older than the configured time window are discarded, so the attempt count always reflects activity within the last N minutes — not a lifetime total:
```python
cutoff = now - timedelta(minutes=TIME_WINDOW_MINUTES)
attempts_by_ip[ip] = [t for t in attempts_by_ip[ip] if t > cutoff]
```
Default configuration: **10 attempts within a 5-minute window**.

### 4. Structured Alert Generation
Once an IP crosses the threshold, a structured JSON alert is built:
```json
{
  "alert_type": "ssh_bruteforce_detected",
  "source_ip": "192.168.73.132",
  "attempt_count": 12,
  "time_window_minutes": 5,
  "first_attempt": "2026-10-31T16:38:13.369890",
  "last_attempt": "2026-10-31T16:38:17.877228",
  "severity": "high",
  "detected_by": "custom_python_ids"
}
```

### 5. Forwarding to Splunk via HEC
The alert is sent as an HTTP POST request directly to Splunk Cloud's HTTP Event Collector, authenticated with a dedicated HEC token, landing in a separate index (`custom_ids_alerts`) without requiring any field extraction on the Splunk side.

### 6. Alert Cooldown
To avoid flooding Splunk with a duplicate alert on every single attempt once the threshold is crossed, a cooldown mechanism ensures only one alert per IP is sent per time window.

## Usage

The script is run manually in the foreground while actively monitoring for brute-force activity:

```bash
pip3 install requests
sudo python3 ids_detector.py
```

Output during monitoring:
[] Monitoring /var/log/auth.log for brute-force patterns...
[] Threshold: 10 attempts / 5 minutes

[INFO] 192.168.73.132 -> 8 failed attempts in last 5min
[INFO] 192.168.73.132 -> 9 failed attempts in last 5min
[INFO] 192.168.73.132 -> 10 failed attempts in last 5min
🚨 [ALERT] Brute-force detected from 192.168.73.132!
✅ Alert sent to Splunk for 192.168.73.132


> This script is designed as a monitoring tool run during an active investigation or test window, rather than as a persistent background service — consistent with how it was executed and validated in this project.

## Detection Verification (Splunk)

```spl
index=custom_ids_alerts alert_type="ssh_bruteforce_detected"
| table _time, source_ip, attempt_count, severity, first_attempt, last_attempt
```

Since the alert arrives as structured JSON, no `rex` or field extraction is needed on the Splunk side — a direct benefit of moving the parsing logic into the script itself.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `THRESHOLD` | `10` | Number of failed attempts that triggers an alert |
| `TIME_WINDOW_MINUTES` | `5` | Sliding window size for counting attempts |
| `HEC_URL` | — | Splunk Cloud HEC endpoint |
| `HEC_TOKEN` | — | Splunk Cloud HEC authentication token |


## Skills Demonstrated

- Python scripting for real-time log monitoring
- Regex-based log parsing
- Sliding time-window algorithm design
- Structured (JSON) alert generation
- SIEM integration via HTTP Event Collector (API-based ingestion, not file-based forwarding)
- Security automation / detection engineering fundamentals

## Disclaimer

This project was conducted entirely within an isolated lab environment using virtual machines owned and controlled by the author, for educational purposes only. No unauthorized systems were accessed or tested.
