### Top 10 Security Event IDs

This visualization highlights the most frequently occurring Windows Security Event IDs collected by Splunk during the observation period. It helps identify dominant authentication, privilege escalation, and account management activities.

SPL Query:

index=* sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort -count
| head 10
