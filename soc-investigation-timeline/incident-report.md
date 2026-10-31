# Incident Investigation Report
## End-to-End SOC Investigation Simulation

**Analyst: Mahmoud
**Date of Investigation:** October 31, 2026
**Environment:** Isolated lab (Kali Linux attacker, Ubuntu Server victim, Splunk Cloud SIEM)
**Classification:** Simulated / Educational — No real-world impact

---

## 1. Executive Summary

This report documents a simulated end-to-end attack chain against a lab victim host, covering reconnaissance, SSH credential brute-forcing, successful authentication, and a reverse shell compromise. Detection evidence for all phases was captured and correlated in Splunk Cloud. The investigation also identifies a timeline inconsistency in the correlated data, which is documented transparently in Section 4.

| Metric | Value |
|---|---|
| Attack phases detected | 3 (Brute-Force, Successful Login, Reverse Shell) |
| Total brute-force attempts logged | 351 |
| Reverse shell connection events logged | 292 |
| Detection source | Splunk Cloud (`ssh_logs`, `network_logs` indexes) |

---

## 2. Attack Chain Overview

```
Reconnaissance (Nmap) → Brute-Force (Hydra) → Successful SSH Login → Reverse Shell (msfvenom/Metasploit)
```

| Phase | Tool(s) | Objective |
|---|---|---|
| 1. Reconnaissance | Nmap | Identify open ports and running services |
| 2. Initial Access | Hydra | Brute-force SSH credentials |
| 3. Privilege/Access Confirmation | SSH | Confirm valid credentials, log in |
| 4. Exploitation / C2 | msfvenom, Metasploit `multi/handler` | Deliver and execute a reverse shell payload |

---

## 3. Timeline of Events (as recorded in Splunk)

| Event Type | First Seen | Last Seen | Event Count |
|---|---|---|---|
| Brute-Force Attempt | 2026-10-31 14:03:45 | 2026-10-31 14:06:52 | 351 |
| Successful SSH Login | 2026-10-31 14:01:21 | 2026-10-31 14:01:21 | 1 |
| Reverse Shell Connection | 2026-10-31 13:58:51 | 2026-10-31 14:23:12 | 292 |

Source query (Splunk SPL):
```spl
(index=ssh_logs ("Failed password" OR "Accepted password")) OR (index=network_logs "4444")
| eval event_type=case(
    match(_raw, "Failed password"), "1 - Brute-Force Attempt",
    match(_raw, "Accepted password"), "2 - Successful SSH Login",
    match(_raw, "4444"), "3 - Reverse Shell Connection"
  )
| where isnotnull(event_type)
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count by event_type
| convert ctime(first_seen) ctime(last_seen)
```

---

## 4. Note on Timeline Discrepancy

The correlated timestamps above do **not** follow the expected attack sequence. Based on the raw data:

- The **Reverse Shell Connection** events begin at 13:58:51 — **before** the Brute-Force Attempt phase even starts (14:03:45).
- The **Successful SSH Login** event (14:01:21) also precedes the bulk of the Brute-Force activity.

**Root cause:** the `ssh_logs` and `network_logs` indexes contain events accumulated across multiple separate lab sessions (including earlier standalone exercises on SSH brute-force detection and reverse shell detection), not a single continuous, uninterrupted execution of the full attack chain in the stated order. The correlation query pulls all matching events within the queried time window regardless of which test run produced them, which is why the phases overlap and appear out of sequence here.

**What this does and does not affect:**
- It does **not** affect the validity of each individual detection mechanism — the brute-force detection, login detection, and reverse-shell detection each work correctly and independently, as verified in their respective standalone projects.
- It **does** mean the specific timestamps above should not be read as a literal, single-session attack narrative. A true end-to-end timeline requires executing recon → brute-force → login → reverse shell in one uninterrupted run and querying only that session's time window.

**Recommended follow-up:** Re-run the full chain in a single session with no prior overlapping test data in the queried window, then re-generate this timeline for an accurate chronological narrative. This is noted as a limitation of this investigation rather than corrected retroactively, to keep this report an honest record of what was actually observed.

---

## 5. Detection Evidence

### 5.1 Reconnaissance
- Nmap scan confirmed port 22 (SSH) open on the victim host.

### 5.2 Brute-Force Attempt Detection
```spl
index=ssh_logs "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port (?<src_port>\d+)"
| stats count by src_ip, user
```
351 failed authentication events were logged from the attacking host, consistent with a Hydra dictionary attack.

### 5.3 Successful Login Detection
```spl
index=ssh_logs "Accepted password"
| rex field=_raw "Accepted password for (?<user>\S+) from (?<src_ip>\S+)"
```
One successful authentication event was recorded, confirming credential compromise.

### 5.4 Reverse Shell Detection
```spl
index=network_logs earliest=-15m latest=now
| rex field=_raw max_match=20 "(?<pair>[\d\.]+:\d+\s+[\d\.]+:\d+)\s+users:"
| mvexpand pair
| rex field=pair "(?<local_ip>[\d\.]+):(?<local_port>\d+)\s+(?<dst_ip>[\d\.]+):(?<dst_port>\d+)"
| where dst_port=4444
```
292 connection-state log entries confirmed an established outbound session from the victim to the attacker on port 4444 — a known Metasploit default and a strong reverse-shell indicator.

*(See `/screenshots` for Nmap output, Hydra execution, Metasploit session, Wireshark capture, and Splunk dashboard panels.)*

---

## 6. Impact Assessment

In a real-world equivalent of this scenario:
- **Confidentiality:** Full compromise — an attacker with a reverse shell has arbitrary command execution on the host.
- **Integrity:** At risk — the attacker could modify files, install persistence mechanisms, or pivot to other hosts.
- **Availability:** At risk — the attacker could disrupt services or use the host for further attacks (e.g., as a pivot point or botnet node).

Given 351 brute-force attempts succeeded in producing one valid credential, this also highlights weak password hygiene as a root-cause contributing factor.

---

## 7. Recommendations

| Area | Recommendation |
|---|---|
| Authentication | Enforce SSH key-based authentication; disable password login |
| Rate limiting | Deploy fail2ban or equivalent to block repeated failed attempts |
| Network | Apply egress filtering to block unexpected outbound connections on non-standard ports |
| Monitoring | Maintain the correlated Splunk search as a standing detection rule, not just an ad hoc query |
| Process | For future simulations, isolate each attack-chain exercise to its own clean time window to avoid cross-session data overlap (see Section 4) |

---

## 8. Conclusion

This simulation successfully demonstrated detection capability across three stages of a realistic SSH-to-reverse-shell attack chain using Splunk Cloud. While the correlated timeline in this run does not reflect a clean single-session sequence due to overlapping historical test data, each detection mechanism was independently validated and found effective. A corrected, single-session re-run is recommended to produce a fully chronological incident narrative for future reporting.

---

*This investigation was conducted entirely within an isolated lab environment using virtual machines owned and controlled by the author, for educational purposes only. No unauthorized systems were accessed or tested.*
