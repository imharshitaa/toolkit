# Splunk Enterprise Deployment

## Overview
Complete implementation guide for deploying Splunk Enterprise as a Security Information and Event Management (SIEM) platform.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Deployment Options](#deployment-options)
4. [Configuration](#configuration)
5. [Data Ingestion](#data-ingestion)
6. [Detection Rules](#detection-rules)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements
- **CPU:** 4+ cores (8+ recommended for production)
- **RAM:** 8GB minimum (16GB+ recommended)
- **Storage:** 100GB+ for logs and indexes
- **OS:** Linux (CentOS, Ubuntu, RHEL) or Windows Server

### Software Dependencies
- Docker (for containerized deployment)
- Python 3.8+
- AWS CLI (for cloud deployment)
- kubectl (for Kubernetes deployment)

### Network Requirements
- Port 8000: Web UI access
- Port 8089: Management port
- Port 9997: Data receiver port
- Port 8088: HTTP Event Collector (HEC)

---

## Quick Start

### Docker Deployment (Recommended for Testing)

```bash
# Deploy Splunk using ToolKit
toolkit deploy soc splunk --environment docker

# Access Splunk Web UI
# URL: http://localhost:8000
# Username: admin
# Password: (set in config or default: changeme)
```

### Local Installation

```bash
# Deploy locally
toolkit deploy soc splunk --environment local

# Start Splunk
/opt/splunk/bin/splunk start

# Enable boot-start
/opt/splunk/bin/splunk enable boot-start
```

---

## Deployment Options

### 1. Docker Deployment

**Best for:** Development, testing, quick demos

```bash
toolkit deploy soc splunk \
  --environment docker \
  --config-file ./my-config.yaml
```

**Container Configuration:**
- Image: `splunk/splunk:latest`
- Auto-restart: Enabled
- Persistent volumes for data retention

### 2. AWS Deployment

**Best for:** Production, scalable infrastructure

```bash
toolkit deploy soc splunk \
  --environment aws \
  --region us-east-1 \
  --instance-type t3.xlarge
```

**AWS Resources Created:**
- EC2 instance with Splunk pre-installed
- Security groups with required ports
- EBS volumes for data storage
- CloudWatch monitoring

### 3. Kubernetes Deployment

**Best for:** Container orchestration, high availability

```bash
toolkit deploy soc splunk \
  --environment kubernetes \
  --config-file ./k8s-config.yaml
```

**K8s Resources:**
- Namespace: `security`
- Deployment with 1+ replicas
- LoadBalancer service
- Persistent volume claims

### 4. On-Premises Deployment

**Best for:** Air-gapped environments, strict compliance

```bash
# Download Splunk installer first
toolkit deploy soc splunk \
  --environment local \
  --skip-validation
```

---

## Configuration

### Index Configuration

Indexes are configured in `config.py`:

```python
INDEXES = [
    {
        'name': 'security',
        'maxDataSizeMB': 500000,
        'frozenTimePeriodInSecs': 2592000,  # 30 days
    },
    {
        'name': 'firewall',
        'maxDataSizeMB': 100000,
        'frozenTimePeriodInSecs': 1296000,  # 15 days
    }
]
```

**Creating Custom Indexes:**

```bash
/opt/splunk/bin/splunk add index <index_name> \
  -homePath /opt/splunk/var/lib/splunk/defaultdb/<index_name>/db \
  -coldPath /opt/splunk/var/lib/splunk/defaultdb/<index_name>/colddb \
  -thawedPath /opt/splunk/var/lib/splunk/defaultdb/<index_name>/thaweddb
```

### Data Input Configuration

#### Syslog Input
```bash
/opt/splunk/bin/splunk add udp 514 \
  -sourcetype syslog \
  -index security
```

#### HTTP Event Collector (HEC)
```bash
/opt/splunk/bin/splunk http-event-collector create \
  -name "toolkit_hec" \
  -uri https://localhost:8088 \
  -index security
```

#### File Monitoring
```bash
/opt/splunk/bin/splunk add monitor /var/log/auth.log \
  -index security \
  -sourcetype linux_secure
```

---

## Data Ingestion

### Forward Data from Universal Forwarder

1. **Install Universal Forwarder on client:**
```bash
wget -O splunkforwarder.tgz 'https://download.splunk.com/...'
tar xzf splunkforwarder.tgz -C /opt/
/opt/splunkforwarder/bin/splunk start --accept-license
```

2. **Configure forwarding:**
```bash
/opt/splunkforwarder/bin/splunk add forward-server \
  <splunk_indexer>:9997
  
/opt/splunkforwarder/bin/splunk add monitor /var/log/ \
  -index security
```

### AWS CloudTrail Integration

1. Configure AWS credentials
2. Install Splunk App for AWS
3. Configure data inputs:

```conf
[aws_cloudtrail]
aws_account = prod_account
aws_iam_role = arn:aws:iam::123456789:role/SplunkRole
sourcetype = aws:cloudtrail
index = cloudtrail
interval = 300
```

### Windows Event Log Collection

Using Splunk Universal Forwarder on Windows:

```powershell
.\splunk.exe add monitor "WinEventLog:Security" -index security
.\splunk.exe add monitor "WinEventLog:System" -index windows
.\splunk.exe add forward-server splunk-server:9997
```

---

## Detection Rules

### Built-in Detections

Located in `detections.md`, including:

1. **Brute Force Detection** (MITRE T1110)
2. **Lateral Movement** (MITRE T1021)
3. **Data Exfiltration** (MITRE T1048)
4. **Privilege Escalation** (MITRE T1548)
5. **Persistence Mechanisms** (MITRE T1053)

### Creating Custom Alerts

```spl
# Navigate to: Settings > Searches, reports, and alerts > New Alert

index=security sourcetype=firewall action=blocked
| stats count by src_ip
| where count > 100
| table _time, src_ip, count
```

**Alert Actions:**
- Email notification
- Webhook to SOAR platform
- Run script
- Create ServiceNow ticket

---

## Attack Simulation

Test your detection capabilities:

```bash
# Run all attack simulations
toolkit scan soc splunk --target localhost:8088 --simulate

# Run specific scenario
toolkit scan soc splunk --target localhost:8088 --simulate \
  --scenario brute_force
```

**Available Scenarios:**
- `brute_force`: Failed login attempts
- `lateral_movement`: Internal network connections
- `data_exfiltration`: Large outbound transfers
- `privilege_escalation`: Sudo abuse
- `persistence`: Cron job creation

---

## Apps and Add-ons

### Essential Apps to Install

1. **Splunk Enterprise Security (ES)**
   - Advanced analytics and correlation
   - Incident review dashboard
   - Risk-based alerting

2. **Splunk Common Information Model (CIM)**
   - Data normalization
   - Standard field names

3. **Splunk App for AWS**
   - CloudTrail, VPC Flow, Config
   - GuardDuty integration

4. **Splunk Add-on for Microsoft Windows**
   - Windows Event Log parsing
   - PowerShell logging

5. **Splunk Add-on for Linux**
   - Syslog parsing
   - Package management logs

### Installing Apps

```bash
# Via Web UI
# Settings > Apps > Find More Apps

# Via CLI
/opt/splunk/bin/splunk install app /path/to/app.spl -auth admin:password
/opt/splunk/bin/splunk restart
```

---

## Performance Tuning

### Search Optimization

```conf
# limits.conf
[search]
max_concurrent_searches = 10
max_searches_per_cpu = 2
ttl = 600

# props.conf
[source::...]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 10000
```

### Indexing Performance

```conf
# indexes.conf
[security]
maxDataSizeMB = 500000
frozenTimePeriodInSecs = 2592000
maxHotBuckets = 10
maxWarmDBCount = 300
```

---

## Monitoring and Maintenance

### Health Check

```spl
index=_internal source=*metrics.log group=per_index_thruput
| chart sum(kb) as total_kb by series
| eval total_mb = round(total_kb/1024, 2)
```

### Disk Usage Monitoring

```bash
/opt/splunk/bin/splunk list index -auth admin:password
/opt/splunk/bin/splunk show datastore-sizes -auth admin:password
```

### Log Rotation

```conf
# Configure in server.conf
[diskUsage]
minFreeSpace = 5000
```

---

## Backup and Recovery

### Backup Strategy

```bash
# Backup configuration
tar czf splunk-backup-$(date +%Y%m%d).tar.gz \
  /opt/splunk/etc/system/local \
  /opt/splunk/etc/apps

# Backup indexes (optional - use cold storage)
tar czf splunk-data-backup.tar.gz /opt/splunk/var/lib/splunk
```

### Disaster Recovery

1. Install Splunk on new server
2. Restore configuration files
3. Restore index data (if needed)
4. Restart Splunk

```bash
tar xzf splunk-backup.tar.gz -C /opt/splunk/
/opt/splunk/bin/splunk start
```

---

## Troubleshooting

### Common Issues

#### 1. Splunk Won't Start

```bash
# Check logs
tail -f /opt/splunk/var/log/splunk/splunkd.log

# Check port conflicts
netstat -tlnp | grep 8000

# Reset admin password
/opt/splunk/bin/splunk cmd splunkd rest --noauth \
  POST /services/admin/users/admin \
  -d password=newpassword
```

#### 2. Data Not Indexing

```bash
# Check input status
/opt/splunk/bin/splunk list inputstatus

# Verify permissions
ls -la /var/log/

# Check ingestion metrics
index=_internal source=*metrics.log group=per_sourcetype_thruput
```

#### 3. High CPU Usage

```spl
# Find expensive searches
index=_audit action=search
| stats count, avg(total_run_time) as avg_runtime by user, search
| sort -avg_runtime
```

### Log Files

- `/opt/splunk/var/log/splunk/splunkd.log` - Main log
- `/opt/splunk/var/log/splunk/metrics.log` - Performance metrics
- `/opt/splunk/var/log/splunk/license_usage.log` - License tracking

---

## Security Best Practices

1. **Change default admin password immediately**
2. **Enable SSL/TLS for web UI**
3. **Configure role-based access control (RBAC)**
4. **Enable audit logging**
5. **Regularly update Splunk and apps**
6. **Use HEC tokens instead of direct index access**
7. **Implement network segmentation**
8. **Enable SAML/LDAP authentication**

---

## Compliance Mapping

### NIST CSF
- Identify: Asset discovery, inventory
- Protect: Access controls, data encryption
- Detect: Real-time monitoring, alerting
- Respond: Incident investigation, forensics
- Recover: Backup, disaster recovery

### ISO 27001
- A.12.4.1: Event logging
- A.12.4.2: Log protection
- A.12.4.3: Administrator logs
- A.12.4.4: Clock synchronization

---

## Additional Resources

- [Splunk Documentation](https://docs.splunk.com/)
- [Splunk Answers](https://community.splunk.com/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [MITRE ATT&CK for Splunk](https://github.com/olafhartong/sysmon-modular)

---

## Support

For ToolKit-specific issues:
- GitHub: https://github.com/imharshitaa/toolkit
- Documentation: See main README.md

For Splunk support:
- Splunk Support Portal
- Community Forums
