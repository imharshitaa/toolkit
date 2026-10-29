# IaC Auditor Module (Cloud Security)

A pure-Python static scanner for Terraform and Docker Compose files. No external
binary, no cloud credentials, no network access — it reads text files on disk and
applies a fixed set of rules.

Status: **implemented**.

## What ToolKit automates

| Command | What it does |
|---|---|
| `toolkit scan cloudsec iacauditor --target <dir>` | Recursively scans `*.tf` and `docker-compose.y*ml` files under `target` (default `.`) |
| `toolkit report cloudsec iacauditor --format html\|markdown` | Renders a report from the most recent scan |

There is no `deploy` operation — this module only reads configuration files, it
never applies, provisions, or modifies infrastructure.

## Why this exists

Cloud security posture management tools (Wiz, Prisma Cloud, AWS Security Hub,
etc.) are commercial SaaS products requiring a paid account. Rather than list
cloud security as catalog-only entirely, this module covers the subset of that
problem space that's fully achievable with static analysis and zero
credentials: catching common Terraform/Compose misconfigurations before they're
ever applied.

## Quick Start

```bash
toolkit scan cloudsec iacauditor --target labs/
toolkit report cloudsec iacauditor --format markdown
```

## What it checks

### Terraform (`*.tf`)
- **Public ingress on sensitive ports** — any `ingress { }` block allowing
  `0.0.0.0/0` on a port in `SENSITIVE_PORTS` (22 SSH, 3389 RDP, 6379 Redis, 27017
  MongoDB, 5432 PostgreSQL, 3306 MySQL, 9200 Elasticsearch, 8088/8089/9997
  Splunk) is flagged `critical`; public ingress on any other port is flagged
  `medium`.
- **Hardcoded secrets** — literal `key = "value"` assignments whose key matches
  `(password|secret|api[_-]?key|access[_-]?key|token)` are flagged `high`.
  Values referencing a variable (`var.foo`) or environment lookup are not
  flagged — only literal strings.

### Docker Compose (`docker-compose.y*ml`)
- **`privileged: true`** on any service — flagged `critical`.
- **`/var/run/docker.sock` volume mount** — flagged `critical` (container
  escape risk).
- **Hardcoded secrets in `environment:`** — non-`${VAR}` values for keys
  matching the same secret-key pattern as above — flagged `high`.

## Reading the result

```bash
toolkit scan cloudsec iacauditor --target labs/
```

On this repo's own `labs/` directory, this currently reports **0 findings** —
`labs/docker/docker-compose.yml` and `labs/terraform/aws_lab.tf` are written to
require secrets via environment variables / Terraform variables with no
defaults, specifically so this scanner has nothing to flag. Point it at a
directory with a hardcoded password or an open security group to see it work —
or temporarily revert one of the lab files to confirm a true-positive case
yourself.

## What this is not

This is a **heuristic, regex/structure-based scanner**, not a full Terraform
plan evaluator (it doesn't understand variable interpolation across files,
modules, or `for_each`/`count` expansion) and not a Trivy/Checkov-equivalent
rule engine. It's deliberately scoped to a small number of high-signal checks it
can apply correctly without a Terraform parser or cloud API access, rather than
claim broad coverage it can't back up.

## Known limitations

- No support for `.tf.json`, HCL `for_each`/`dynamic` blocks, or cross-file
  variable resolution — a `cidr_blocks = [var.allowed_cidr]` referencing a
  variable defined with an unsafe default elsewhere won't be caught.
- Terraform resource types beyond AWS security-group-style `ingress` blocks
  (e.g., Azure NSGs, GCP firewall rules) are not specifically modeled.
