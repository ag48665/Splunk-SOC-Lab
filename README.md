\# Splunk SOC Lab



\## Overview



This project documents the creation of a Security Operations Center (SOC) lab using Splunk Enterprise and Windows Security Event Logs.



The goal of this lab is to simulate basic SOC analyst activities including:



\- Log collection

\- Event monitoring

\- Security investigations

\- Detection engineering

\- Dashboard creation

\- Windows Security Event analysis



\---



\## Environment



| Component | Details |

|------------|------------|

| SIEM | Splunk Enterprise 10.4 |

| Endpoint | Windows 11 |

| Data Source | Windows Security Event Logs |

| Log Type | WinEventLog:Security |



\---



\## Data Collection



Windows Security Event Logs were ingested into Splunk using Local Event Log monitoring.



Collected events include:



\- Successful Logons (4624)

\- Failed Logons (4625)

\- Privileged Logons (4672)

\- User and Account Activity

\- Security Auditing Events



\---



\## Detection Use Cases



\### Failed Logons Detection



Detects unsuccessful authentication attempts.



```spl

index=\* sourcetype="WinEventLog:Security" EventCode=4625

| stats count by Account\_Name

| sort -count

```



MITRE ATT\&CK:



\- T1110 - Brute Force



\---



\### Top 10 Security Event IDs



Displays the most common Windows Security Events.



```spl

index=\* sourcetype="WinEventLog:Security"

| stats count by EventCode

| sort -count

| head 10

```



\---



\## Dashboards



\### SOC Security Overview



Current dashboard panels:



\- Failed Logons Detection

\- Top 10 Security Event IDs

\- Windows Security Event Distribution



\---



\## Screenshots



\### Failed Logons Detection



!\[Failed Logons](screenshots/failed\_logons\_detection.png)



\### Top 10 Security Event IDs



!\[Top 10 Events](screenshots/top\_10\_security\_event\_ids.png)



\### Windows Security Event Distribution



!\[Security Events](screenshots/windows\_security\_event\_distribution.png)



\---



\## Skills Demonstrated



\- Splunk Enterprise Administration

\- Windows Event Log Analysis

\- SPL (Search Processing Language)

\- Security Monitoring

\- Detection Engineering

\- Dashboard Development

\- SIEM Operations



\---



\## Future Improvements



\- Install Sysmon

\- Create custom alerts

\- Add PowerShell monitoring

\- Build incident response playbooks

\- Map detections to MITRE ATT\&CK

