Detection Name: Failed Logons

Event ID:
4625

Purpose:
Detect unsuccessful authentication attempts.

SPL:
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| sort -count

MITRE ATT&CK:
T1110 - Brute Force