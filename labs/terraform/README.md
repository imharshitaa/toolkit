# Terraform Lab (AWS)

Standalone Terraform that provisions a single-instance Splunk Enterprise deployment
on AWS, plus a GuardDuty detector and a CloudTrail trail for baseline account
visibility. This is infrastructure-as-code for a *disposable lab environment*, not
a production security architecture.

This is applied directly with `terraform`, independent of the `toolkit` CLI —
`toolkit deploy soc splunk --environment aws` takes a separate, lighter-weight path
through `boto3` (see `modules/SOC/splunk/deploy.py::deploy_aws`) that launches a bare
EC2 instance without the VPC/GuardDuty/CloudTrail resources this Terraform config
creates. Use this Terraform config when you want the fuller lab environment with
monitoring baked in; use `toolkit deploy` for a quick, minimal instance.

## Prerequisites

- Terraform >= 1.0
- AWS credentials configured (`aws configure`, environment variables, or an
  assumed role) — Terraform uses your own credential chain; nothing here embeds
  AWS credentials.

## Required variables

Two variables have **no default on purpose** — Terraform will refuse to `apply`
until you supply them, which is intentional: a wide-open default here would defeat
the point of restricting access.

| Variable | Description |
|---|---|
| `admin_cidr` | CIDR allowed to reach SSH, the Splunk Web UI, and the HTTP Event Collector — e.g. `"203.0.113.4/32"` for your own IP. **Do not use `0.0.0.0/0`.** |
| `splunk_password` | Initial Splunk admin password. Marked `sensitive = true` in Terraform's output handling. Supply via `TF_VAR_splunk_password` or a `.tfvars` file that is **never committed**. |

Variables with defaults you may still want to override:

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `us-east-1` | AWS region |
| `vpc_cidr` | `10.0.0.0/16` | VPC CIDR block |
| `environment` | `toolkit-lab` | Tag/name prefix for all resources |
| `splunk_instance_type` | `t3.xlarge` | EC2 instance type for Splunk |

## Usage

```bash
cd labs/terraform

export TF_VAR_admin_cidr="<your-ip>/32"
export TF_VAR_splunk_password="<a-real-password>"

terraform init
terraform plan
terraform apply
```

## What gets created

- A VPC with a public and a private subnet, an internet gateway, and a public route
  table.
- A security group restricting SSH (22), the Splunk Web UI (8000), and the HEC port
  (8088) to `admin_cidr`; the Splunk Management port (8089) and Receiver port (9997)
  to `vpc_cidr` only (not exposed to the internet at all).
- A single EC2 instance running Amazon Linux 2, bootstrapped via
  `scripts/splunk_install.sh` (templated with your `splunk_password`) to install and
  start Splunk Enterprise with a 100GB gp3 root volume.
- An IAM role/instance profile attaching the `CloudWatchAgentServerPolicy`.
- A GuardDuty detector (S3 + Kubernetes audit log data sources enabled).
- A CloudTrail trail (all regions, all management events) writing to a
  purpose-created S3 bucket.

Outputs: `vpc_id`, `splunk_public_ip`, `splunk_web_url`, `guardduty_detector_id`,
`cloudtrail_arn`.

## Known limitation

`user_data` (which embeds `splunk_password`) is stored in plaintext in both the EC2
instance metadata service and Terraform state. This is a general limitation of
user-data bootstrapping, not specific to this config — for anything beyond a
disposable lab, pull the password from AWS Secrets Manager at boot time instead of
embedding it at launch. This tradeoff is documented, not hidden.

## Tear down

```bash
terraform destroy
```

This deletes the EC2 instance, VPC, GuardDuty detector, CloudTrail trail, and the
CloudTrail S3 bucket (which must be empty — Terraform will fail to destroy it if
CloudTrail has already written logs to it; empty the bucket manually first if so).
