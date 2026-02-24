# Splunk Detection Rules

## Overview
This document contains detection logic and search queries for identifying security threats in Splunk.

## Table of Contents
1. [Brute Force Detection](#brute-force-detection)
2. [Lateral Movement](#lateral-movement)
3. [Data Exfiltration](#data-exfiltration)
4. [Privilege Escalation](#privilege-escalation)
5. [Persistence Mechanisms](#persistence-mechanisms)

---

## Brute Force Detection

### Failed Login Attempts - High Volume
**MITRE ATT&CK:** T1110 - Brute Force

**Description:** Detects multiple failed login attempts from a single source IP

**SPL Query:**
```spl
index=security sourcetype=linux_secure OR sourcetype=WinEventLog:Security 
(action="login_failed" OR EventCode=4625)
| stats count by src_ip, user 
| where count > 5
| eval severity="high"
| table _time, src_ip, user, count, severity
```

**Detection Logic:**
- Looks for failed authentication events
- Groups by source IP and username
- Alerts when count exceeds 5 attempts
- Severity: High

**Response Actions:**
1. Block source IP at firewall
2. Review user account for compromise
3. Enable MFA if not already enabled

---

## Lateral Movement

### Unusual Network Connections Between Internal Hosts
**MITRE ATT&CK:** T1021 - Remote Services

**Description:** Detects suspicious remote connections between internal systems

**SPL Query:**
```spl
index=security sourcetype=network_traffic 
(dest_port=3389 OR dest_port=22 OR dest_port=5985)
src_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| stats count by src_ip, dest_ip, dest_port, user
| where count > 3
| eval technique="T1021"
| table _time, src_ip, dest_ip, dest_port, user, count, technique
```

**Detection Logic:**
- Monitors RDP (3389), SSH (22), WinRM (5985) connections
- Filters for internal-to-internal traffic
- Flags multiple connections in short timeframe

**Response Actions:**
1. Investigate source system for compromise
2. Review destination system logs
3. Isolate affected systems if confirmed malicious

---

## Data Exfiltration

### Large Outbound Data Transfer
**MITRE ATT&CK:** T1048 - Exfiltration Over Alternative Protocol

**Description:** Identifies unusually large data transfers to external destinations

**SPL Query:**
```spl
index=security sourcetype=firewall_logs OR sourcetype=proxy_logs
action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where total_bytes > 100000000
| eval total_mb=round(total_bytes/1024/1024,2)
| eval severity="critical"
| table _time, src_ip, dest_ip, dest_port, total_mb, severity
```

**Detection Logic:**
- Sums outbound bytes per source/destination pair
- Alerts on transfers exceeding 100MB
- Focuses on external destinations

**Response Actions:**
1. Block destination IP/domain
2. Capture network traffic for forensics
3. Investigate source system thoroughly
4. Review data classification of transferred files

---

## Privilege Escalation

### Sudo Command Execution by Non-Admin User
**MITRE ATT&CK:** T1548 - Abuse Elevation Control Mechanism

**Description:** Detects sudo usage by users not in admin group

**SPL Query:**
```spl
index=security sourcetype=linux_secure command="sudo*"
NOT user IN ("admin", "root", "sysadmin")
| stats count by host, user, command
| eval technique="T1548"
| eval severity="high"
| table _time, host, user, command, count, technique, severity
```

**Detection Logic:**
- Monitors sudo command execution
- Excludes known admin accounts
- Flags any usage by regular users

**Response Actions:**
1. Review user account permissions
2. Investigate commands executed
3. Check for unauthorized privilege changes
4. Audit sudo configuration

---

## Persistence Mechanisms

### New Cron Job Creation
**MITRE ATT&CK:** T1053.003 - Scheduled Task/Job: Cron

**Description:** Detects creation of new cron jobs

**SPL Query:**
```spl
index=security sourcetype=linux_secure OR sourcetype=syslog
("cron" OR "crontab") (created OR added OR modified)
| rex field=message "crontab \((?<user>\w+)\)"
| eval technique="T1053.003"
| table _time, host, user, message, technique
```

**Detection Logic:**
- Monitors cron/crontab modifications
- Extracts user making changes
- Alerts on any cron job creation

**Response Actions:**
1. Review new cron job contents
2. Verify legitimacy with system owner
3. Remove if unauthorized
4. Check for other persistence mechanisms

---

## Advanced Threat Hunting Queries

### User Account Created Outside Business Hours
```spl
index=security sourcetype=WinEventLog:Security EventCode=4720
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 18
| table _time, host, TargetUserName, SubjectUserName, hour
```

### Suspicious PowerShell Execution
```spl
index=security sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational
EventCode=4104
(ScriptBlockText="*downloadstring*" OR ScriptBlockText="*invoke-expression*" 
OR ScriptBlockText="*bypass*" OR ScriptBlockText="*-enc*")
| table _time, host, User, ScriptBlockText
```

### Unusual Process Parent-Child Relationship
```spl
index=security sourcetype=Sysmon EventCode=1
| stats count by ParentImage, Image
| where (ParentImage="*cmd.exe" AND Image="*powershell.exe")
   OR (ParentImage="*winword.exe" AND Image="*cmd.exe")
   OR (ParentImage="*excel.exe" AND Image="*wscript.exe")
| table ParentImage, Image, count
```

---

## Alert Configuration

### Recommended Alert Thresholds
- **Brute Force:** 5 failed attempts in 5 minutes
- **Lateral Movement:** 3 connections in 10 minutes
- **Data Exfiltration:** 100MB in 1 hour
- **Privilege Escalation:** Any occurrence
- **Persistence:** Any new cron/scheduled task

### Alert Actions
1. Send email to SOC team
2. Create ticket in ITSM
3. Send to SOAR for automated response
4. Log to incident tracking system

---

## Correlation Searches

### Multi-Stage Attack Detection
```spl
index=security
| transaction src_ip maxspan=1h
| where eventcount > 1
| search (technique="T1110" AND technique="T1021" AND technique="T1048")
| table _time, src_ip, techniques, eventcount
```

This correlation search identifies attack chains across multiple MITRE ATT&CK techniques.

---

## Dashboard Recommendations

1. **Executive Dashboard:** High-level KPIs and trend analysis
2. **SOC Dashboard:** Real-time alerts and incident status
3. **Threat Hunt Dashboard:** Advanced analytics and investigations
4. **Compliance Dashboard:** Audit logs and policy violations

---

## Maintenance

- Review and tune detections monthly
- Update based on new threat intelligence
- Remove false positive sources
- Document all changes
