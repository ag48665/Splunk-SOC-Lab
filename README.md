# Splunk-SOC-Lab
### Windows Security Event Distribution

This panel displays the most frequently occurring Windows Security Event IDs collected by Splunk. It provides a high-level overview of authentication activity, privilege assignments, account management actions, and other security-relevant events.

SPL Query:

index=* sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort -count
