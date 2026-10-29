# labs/

Local, disposable environments for exercising ToolKit's modules — nothing in
here is required to install or import the `toolkit` package itself.

| Directory | Purpose |
|---|---|
| [`docker/`](docker/README.md) | Docker Compose stack: Splunk, OWASP ZAP, Wazuh, and DVWA as a safe local scan target. Backs the SOC/Splunk, SOC+EDR/Wazuh, and AppSec/ZAP modules. |
| [`terraform/`](terraform/README.md) | Standalone Terraform for a fuller AWS Splunk lab (VPC, locked-down security group, GuardDuty, CloudTrail) — applied independently of the `toolkit` CLI. |

Both are also useful as intentionally-real-but-safe targets for the
Cloud Security module: `toolkit scan cloudsec iacauditor --target labs/` scans
this directory's own Terraform and Compose files for misconfigurations.
