# Splunk SOC Lab

## Overview

This project documents the creation of a Security Operations Center (SOC) lab using Splunk Enterprise and Windows Security Event Logs.

The goal of this lab is to simulate basic SOC analyst activities including:

* Log collection
* Event monitoring
* Security investigations
* Detection engineering
* Dashboard creation
* Windows Security Event analysis

---

## Environment

| Component   | Details                     |
| ----------- | --------------------------- |
| SIEM        | Splunk Enterprise 10.4      |
| Endpoint    | Windows 11                  |
| Data Source | Windows Security Event Logs |
| Log Type    | WinEventLog:Security        |

---

## Data Collection

Windows Security Event Logs were ingested into Splunk using Local Event Log monitoring.

Collected events include:

* Successful Logons (4624)
* Failed Logons (4625)
* Privileged Logons (4672)
* User Account Creation (4720)
* Security Auditing Events

---

## Detection Use Cases

### Failed Logons Detection

Detects unsuccessful authentication attempts.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| sort -count
```

**MITRE ATT&CK:** T1110 - Brute Force

---

### User Account Creation Detection

Detects creation of new local user accounts.

```spl
index=* EventCode=4720
```

**MITRE ATT&CK:** T1136 - Create Account

---

### Privileged Logons Detection

Detects logons receiving elevated privileges.

```spl
index=* EventCode=4672
| stats count by Account_Name
| sort -count
| head 10
```

**MITRE ATT&CK:** T1078 - Valid Accounts

---

### Top 10 Security Event IDs

Displays the most common Windows Security Events.

```spl
index=* sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort -count
| head 10
```

---

## Dashboards

### SOC Security Overview

Current dashboard panels:

* Failed Logons Detection
* User Account Creation Detection
* Privileged Logons Detection
* Top 10 Security Event IDs

---

## Screenshots

### Failed Logons Detection

![Failed Logons](screenshots/failed_logons_detection.png)

### User Account Creation Detection

![User Account Creation](screenshots/user_account_creation_detection.png)

### Privileged Logons Detection

![Privileged Logons](screenshots/privileged_logons_detection.png)

### Top 10 Security Event IDs

![Top 10 Events](screenshots/top_10_security_event_ids.png)

### Windows Security Event Distribution

![Security Events](screenshots/windows_security_event_distribution.png)

---

## Skills Demonstrated

* Splunk Enterprise Administration
* Windows Event Log Analysis
* SPL (Search Processing Language)
* Security Monitoring
* Detection Engineering
* Dashboard Development
* SIEM Operations
* Threat Detection

---

## Future Improvements

* Install Sysmon
* Add Sysmon Event ID detections
* Create custom alerts
* Add PowerShell monitoring
* Build incident response playbooks
* Map detections to MITRE ATT&CK
* Create SOC analyst dashboards
