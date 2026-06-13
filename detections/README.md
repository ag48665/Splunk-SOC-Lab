# Detection Library

This document contains detection use cases developed during the Splunk SOC Lab project.

## Failed Logons Detection

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| sort -count
```

MITRE ATT&CK: T1110 - Brute Force

---

## Brute Force Detection

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count as FailedAttempts by Account_Name
| where FailedAttempts > 5
```

MITRE ATT&CK: T1110 - Brute Force

---

## Successful Logon Monitoring

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4624
| stats count by Account_Name
| sort -count
```

MITRE ATT&CK: T1078 - Valid Accounts

---

## User Account Creation Detection

```spl
index=* EventCode=4720
```

MITRE ATT&CK: T1136 - Create Account

---

## PowerShell Execution Detection

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "powershell.exe"
```

MITRE ATT&CK: T1059.001 - PowerShell

---

## Command Prompt Execution Detection

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "cmd.exe"
```

MITRE ATT&CK: T1059.003 - Windows Command Shell
