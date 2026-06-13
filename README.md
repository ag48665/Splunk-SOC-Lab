## Sysmon Threat Hunting

Sysmon was deployed to enhance endpoint visibility and provide advanced process and network monitoring capabilities.

### Sysmon Data Source

| Component         | Details                                             |
| ----------------- | --------------------------------------------------- |
| Source            | Microsoft-Windows-Sysmon/Operational                |
| Sourcetype        | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |
| Collection Method | Local Event Log Collection                          |
| Index             | main                                                |

---
### Sysmon Event ID Distribution

This search extracts Sysmon Event IDs from XML logs and summarizes the most common event types.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<SysmonEventID>\d+)</EventID>"
| stats count by SysmonEventID
---

### Process Creation Monitoring

Monitor newly created processes.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
```

**MITRE ATT&CK:** T1059 - Command and Scripting Interpreter

---

### PowerShell Execution Detection

Detect execution of PowerShell commands.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
powershell.exe
```

**MITRE ATT&CK:** T1059.001 - PowerShell

---

### Command Prompt Execution Detection

Detect execution of cmd.exe.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
cmd.exe
```

**MITRE ATT&CK:** T1059.003 - Windows Command Shell

---

### Network Connection Monitoring

Monitor outbound network connections.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
```

**MITRE ATT&CK:** T1049 - System Network Connections Discovery

---

### File Creation Monitoring

Detect creation of files by monitored processes.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11
```

**MITRE ATT&CK:** T1105 - Ingress Tool Transfer

---
### PowerShell Execution Detection

Detects execution of PowerShell commands.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
powershell.exe
```

![PowerShell Detection](screenshots/sysmon_powershell.png)
---
### Command Prompt Execution Detection

Detects execution of cmd.exe.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
cmd.exe

---
### Sysmon Screenshots

![Sysmon Events](screenshots/sysmon_events.png)


## Future Improvements

* Create real-time Splunk alerts
* Develop correlation searches
* Integrate Sigma rules
* Build custom SOC dashboards
* Create phishing detection use cases
* Develop brute-force detection playbooks
* Add MITRE ATT&CK coverage matrix
* Simulate attack scenarios using Atomic Red Team

