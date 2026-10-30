# SSH Brute-Force Detection with Splunk

Part of the [`soc-projects`](https://github.com/Mahmoud320-ht/soc-projects) repository.

A hands-on SOC (Security Operations Center) project simulating an SSH brute-force attack in an isolated lab, then detecting it end-to-end using Splunk Cloud — from raw log ingestion to a working dashboard and a threshold-based alert.

## Overview

This project walks through the full detection lifecycle an analyst follows in practice:

```
Attack Simulation  →  Log Collection  →  Analysis (SPL)  →  Dashboard  →  Threshold Alert
```

An attacker (Kali Linux) brute-forces SSH credentials against a victim host (Ubuntu). The victim forwards its authentication logs to Splunk Cloud in real time, where custom searches surface the attack pattern, a dashboard visualizes it, and a scheduled alert flags it automatically.

## Lab Architecture

| Machine | Role | Purpose |
|---|---|---|
| Kali Linux | Attacker | Reconnaissance and brute-force tooling |
| Ubuntu Server | Victim | Runs SSH; logs to `/var/log/auth.log` |
| Splunk Cloud | SIEM | Ingests, indexes, analyzes, and alerts on logs |

All machines were virtual machines running on an isolated network, owned and controlled by the author.

## Tools Used

- **Kali Linux** — attack platform
- **Nmap** — service/port reconnaissance
- **Hydra** — SSH brute-force simulation
- **Splunk Cloud** — log ingestion, search (SPL), dashboarding, alerting
- **Splunk Universal Forwarder** — forwards `auth.log` from the victim to Splunk Cloud over SSL

## Implementation

### 1. Victim Setup
Installed and enabled `openssh-server` on Ubuntu, and confirmed authentication events are written to `/var/log/auth.log`.

### 2. Log Forwarding Pipeline
- Installed Splunk Universal Forwarder on the Ubuntu victim
- Installed the Splunk Cloud credentials package (`splunkclouduf.spl`) to establish a secure, SSL-encrypted connection to Splunk Cloud
- Created a dedicated index, `ssh_logs`
- Configured `inputs.conf` to monitor the log file:
  ```ini
  [monitor:///var/log/auth.log]
  sourcetype = linux_secure
  index = ssh_logs
  ```
- Verified connectivity with `splunk list forward-server` and confirmed events landing in `index=ssh_logs`

### 3. Reconnaissance
```bash
nmap -sV -p 22 <victim-ip>
```
Confirmed port 22 was open and running SSH — the same first step a real attacker takes before targeting a service.

### 4. Attack Simulation
```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<victim-ip> -t 4
```
Generated a high volume of failed authentication attempts against the victim, reproducing a realistic credential-stuffing/brute-force scenario.

### 5. Detection Searches (SPL)

See [`splunk-queries/spl-queries.spl`](./splunk-queries/spl-queries.spl) for the full set. Highlights:

**Failed login attempts, parsed into fields:**
```spl
index=ssh_logs "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port (?<src_port>\d+)"
| table _time, src_ip, user, src_port
```

**Top attacking source IPs:**
```spl
index=ssh_logs "Failed password"
| rex field=_raw "from (?<src_ip>\S+)"
| stats count by src_ip
| sort -count
```

**Top attempted usernames:**
```spl
index=ssh_logs "Failed password"
| rex field=_raw "for (invalid user )?(?<user>\S+) from"
| stats count by user
| sort -count
```

**Failed attempts over time:**
```spl
index=ssh_logs "Failed password"
| timechart span=1m count
```

### 6. Dashboard
Built a Splunk dashboard, **SSH Brute-Force Monitoring**, combining the searches above into:
- A timeline of failed login attempts
- Top attacking source IPs (bar/pie chart)
- Top attempted usernames (bar chart)
- A detailed, searchable event table

### 7. Threshold-Based Alert
Detection logic: flag any source IP responsible for more than 10 failed attempts within a 5-minute window — a standard credential-abuse threshold.

```spl
index=ssh_logs "Failed password"
| rex field=_raw "from (?<src_ip>\S+)"
| bucket _time span=5m
| stats count by src_ip, _time
| where count > 10
```

Configured as a **Scheduled Alert**, running every 5 minutes, triggering when results > 0.

## Results

- Simulated and detected an SSH brute-force attack end-to-end, in near real time
- Confirmed reliable log forwarding from the victim to Splunk Cloud over SSL
- Built working visibility into attacker source IPs, targeted usernames, and attack timing
- Alert reliably triggered during active brute-force attempts, visible under **Triggered Alerts**

## Mitigation Recommendations

Controls that would reduce this risk in a production environment:
- **fail2ban** — automatically block IPs after repeated failed attempts
- **SSH key-based authentication** — disable password authentication entirely
- **Rate limiting / connection throttling** at the firewall level
- **MFA for SSH**, where supported
- **Non-default SSH port** as a minor layer of obscurity (not a substitute for the above)

## Repository Contents

```
ssh-bruteforce-detection-splunk/
├── README.md
├── splunk-queries/
│   └── spl-queries.spl        # All SPL queries used, documented
├── configs/
│   └── inputs.conf.example    # Sanitized forwarder config
└── screenshots/                # Evidence: scans, attack, dashboard, alerts
```

## Skills Demonstrated

- Linux system administration (services, log files, permissions)
- Offensive security tooling (Nmap, Hydra, Metasploit)
- SIEM operations (Splunk Cloud, Universal Forwarder, indexes)
- SPL (Search Processing Language) for log analysis
- Security monitoring design: dashboards and threshold-based alerting

## Disclaimer

This project was conducted entirely within an isolated lab environment using virtual machines owned and controlled by the author, for educational purposes only. No unauthorized systems were accessed or tested.
