# Splunk Module (SOC)

Deploys Splunk Enterprise, sends simulated attack telemetry to it over HTTP Event
Collector (HEC), and renders a report from the most recent run.

Status: **implemented**.

## Table of Contents
1. [What ToolKit automates](#what-toolkit-automates)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Deployment Options](#deployment-options)
5. [Configuration](#configuration)
6. [Attack Simulation](#attack-simulation)
7. [Detection Rules Reference](#detection-rules-reference)
8. [Manual Splunk Administration Reference](#manual-splunk-administration-reference)
9. [Troubleshooting](#troubleshooting)

---

## What ToolKit automates

| Command | What it does |
|---|---|
| `toolkit deploy soc splunk --environment docker` | Runs a Splunk Enterprise container via the Docker SDK (`modules/SOC/splunk/deploy.py::deploy_docker`) |
| `toolkit deploy soc splunk --environment local` | Validates config and prints local-install guidance (no actual installer download is performed by ToolKit) |
| `toolkit deploy soc splunk --environment aws` | Launches a single EC2 instance via `boto3` using your own AWS credential chain (`deploy_aws`) — see [Known limitations](#known-limitations) |
| `toolkit deploy soc splunk --environment kubernetes` | Writes a Deployment/Service manifest and applies it via `kubectl` (`deploy_kubernetes`) |
| `toolkit scan soc splunk --target <host:hec_port> --simulate --scenario <name>` | Generates synthetic attack telemetry and sends it to Splunk's HEC, or logs it locally if no reachable HEC is configured |
| `toolkit report soc splunk --format html\|markdown` | Renders a report from the most recent simulate run |

Everything else in this document below **Manual Splunk Administration Reference** is
operational knowledge for working with Splunk itself once it's running — none of it
is invoked by ToolKit's CLI. It's included because a SOC module without any
detection-engineering context isn't very useful on its own.

## Prerequisites

### System Requirements
- **CPU:** 4+ cores recommended
- **RAM:** 8GB minimum
- **Storage:** enough for log retention, depends on ingestion volume
- **OS:** any Docker host (for `--environment docker`), or Linux for a local install

### Software Dependencies
- Docker, for `--environment docker` (the only environment verified in this repo's test suite and this environment, see [Known limitations](#known-limitations))
- AWS credentials in your own environment, for `--environment aws`
- `kubectl` configured against a cluster, for `--environment kubernetes`

### Ports
- 8000: Web UI
- 8089: Management port
- 9997: Data receiver port
- 8088: HTTP Event Collector (HEC)

---

## Quick Start

```bash
cd labs/docker
cp .env.example .env   # set SPLUNK_PASSWORD and SPLUNK_HEC_TOKEN — see labs/docker/README.md

cd ../..
toolkit deploy soc splunk --environment docker
# Web UI: http://localhost:8000  (user: admin, password: whatever you set in .env)

toolkit scan soc splunk --target localhost:8088 --simulate --scenario brute_force
toolkit report soc splunk --format markdown
```

There is no built-in default password: `modules/SOC/splunk/config.py` reads
`SPLUNK_PASSWORD` from the environment, falling back to the placeholder
`changeme` only so that `--dry-run`/validation flows have something to check —
`validate(require_non_default_password=True)` refuses to proceed with a real
deployment while the password is still `changeme`.

---

## Deployment Options

### Docker

```bash
toolkit deploy soc splunk --environment docker
```

Runs `splunk/splunk:latest` with the ports above, licensed in "free/trial"
accept-license mode, with `SPLUNK_PASSWORD` passed through as the container's
admin password.

### AWS

```bash
toolkit deploy soc splunk --environment aws --region us-east-1 --instance-type t3.xlarge
```

Launches a single EC2 instance (default AMI: Amazon Linux 2) via `boto3`, using
*your own* AWS credentials (from your environment/`~/.aws/credentials` — ToolKit
never stores or embeds AWS credentials). The admin password is passed through EC2
user-data, which is visible in plaintext via the instance metadata service — this
is a known limitation of user-data bootstrapping in general, not something unique
to ToolKit. For a more complete lab setup with a locked-down security group,
GuardDuty, and CloudTrail, see `labs/terraform/` instead, which takes a separate
Terraform-based path.

### Kubernetes

```bash
toolkit deploy soc splunk --environment kubernetes
```

Writes a manifest to `./splunk-k8s.yaml` and applies it with `kubectl apply -f`,
against whatever cluster your current `kubectl` context points to.

### Local

```bash
toolkit deploy soc splunk --environment local
```

Validates configuration and prints the manual installation steps — ToolKit does
not download or install the Splunk binary itself for this path.

---

## Configuration

Settings live in `modules/SOC/splunk/config.py`:

```python
SPLUNK_CONFIG = {
    'admin_password': os.getenv('SPLUNK_PASSWORD', 'changeme'),
    'web_port': 8000,
    'mgmt_port': 8089,
    'splunkd_port': 9997,
    ...
}
```

`INDEXES` defines the index names ToolKit's Docker deployment is aware of
(`security`, `firewall`, `endpoint`, `cloudtrail`) — these are **suggested
index definitions for your own Splunk configuration**, not something ToolKit
provisions automatically inside the container today.

`DATA_INPUTS['http']['token']` reads `SPLUNK_HEC_TOKEN` from the environment —
this is what `toolkit scan soc splunk --simulate` sends events to.

---

## Attack Simulation

```bash
toolkit scan soc splunk --target localhost:8088 --simulate
toolkit scan soc splunk --target localhost:8088 --simulate --scenario brute_force
```

**Available scenarios** (`modules/SOC/splunk/simulate.py`):
- `brute_force` — failed login attempt bursts
- `lateral_movement` — internal host-to-host connection patterns
- `data_exfiltration` — large outbound transfer events
- `privilege_escalation` — sudo/privilege-change events
- `persistence` — cron/scheduled-task creation events

If `SPLUNK_HEC_TOKEN` is unset or the HEC endpoint is unreachable, events are
written to a local JSON log instead of being silently dropped, and the CLI tells
you which path was taken.

---

## Detection Rules Reference

`detections.md` in this directory contains SPL detection queries and
threat-hunting searches for the five MITRE ATT&CK techniques the simulate
scenarios above generate telemetry for (T1110, T1021, T1048, T1548, T1053.003).
These are meant to be pasted into Splunk's search bar manually — ToolKit does not
create saved searches or alerts in Splunk for you.

---

## Manual Splunk Administration Reference

The following is general Splunk operational knowledge, useful once you have a
Splunk instance running — none of it is executed by ToolKit.

### Creating a custom index
```bash
/opt/splunk/bin/splunk add index <index_name> \
  -homePath /opt/splunk/var/lib/splunk/defaultdb/<index_name>/db \
  -coldPath /opt/splunk/var/lib/splunk/defaultdb/<index_name>/colddb \
  -thawedPath /opt/splunk/var/lib/splunk/defaultdb/<index_name>/thaweddb
```

### Forwarding data from a Universal Forwarder
```bash
/opt/splunkforwarder/bin/splunk add forward-server <splunk_indexer>:9997
/opt/splunkforwarder/bin/splunk add monitor /var/log/ -index security
```

### Creating an alert from a search
```spl
index=security sourcetype=firewall action=blocked
| stats count by src_ip
| where count > 100
| table _time, src_ip, count
```
Configure the alert's action (email, webhook, scripted response, ticketing
integration) through Splunk's own Settings UI — ToolKit has no integration with
any of those systems.

### Common apps you might install yourself
`Splunk_TA_linux`, `Splunk_TA_windows`, `Splunk_TA_aws`, `Splunk_Security_Essentials`,
`Splunk_CIM` — installed via Splunk's own Web UI (Settings > Apps) or
`splunk install app <file>.spl`. ToolKit does not install or manage Splunk apps.

### Backup
```bash
tar czf splunk-backup-$(date +%Y%m%d).tar.gz \
  /opt/splunk/etc/system/local /opt/splunk/etc/apps
```

---

## Troubleshooting

**Splunk won't start in the container**
```bash
docker logs splunk-enterprise
```

**No events showing up after `--simulate`**
- Check the CLI output for whether it took the HEC path or the local-log fallback.
- If using HEC, confirm `SPLUNK_HEC_TOKEN` matches a token actually configured on
  the Splunk instance (ToolKit does not create the HEC token for you — create it
  via Settings > Data Inputs > HTTP Event Collector first).

**`toolkit deploy soc splunk --environment aws` fails immediately**
- `modules/SOC/splunk/deploy.py` catches `botocore.exceptions.NoCredentialsError`
  and reports that no AWS credentials were found — set up your own AWS credential
  chain (`aws configure`, environment variables, or an assumed role) first.

## Known limitations

- Only the Docker deployment path and the simulate/report flow are covered by this
  repo's automated tests (with Docker/`requests` mocked — see `tests/README.md`).
  AWS and Kubernetes deploys require real cloud/cluster access this project does
  not have and are not under test.
- Index creation, HEC token creation, and app installation inside a running Splunk
  instance are manual steps today — ToolKit validates and deploys the instance, it
  does not configure it post-boot.
