# ToolKit

**A command-line framework for deploying, scanning, and reporting across open-source security tooling — no third-party SaaS credentials required.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: 102 passing](https://img.shields.io/badge/tests-102%20passing-brightgreen.svg)](#testing)

ToolKit is a single CLI (`toolkit`) that drives real security tools — Splunk, Wazuh,
OWASP ZAP, nmap, Trivy, plus two pure-Python static scanners — through one consistent
`deploy` / `scan` / `report` interface. Every result is backed by real output from the
underlying tool, persisted to disk, and rendered into an HTML or Markdown report.

The CLI also catalogs ~19 enterprise security products (CrowdStrike, Microsoft
Sentinel, AWS GuardDuty, Tenable, Qualys, etc.) for domain-coverage reference via
`toolkit list-tools` — those are commercial SaaS products by definition and require
the vendor's own account, so they're listed, not reimplemented. See
[Implemented vs. Catalog Tools](#implemented-vs-catalog-tools) for the exact split.

## Who this is for

Security engineers who want one CLI to drive a local SOC/AppSec/NetSec lab — spin up
Splunk or Wazuh, run a ZAP scan against a local target, sweep a subnet with nmap,
scan a container image with Trivy, or statically audit Terraform/Docker Compose and
LLM transcripts for common misconfigurations — without juggling five different tool
invocations and five different report formats.

## Table of Contents

- [Implemented vs. Catalog Tools](#implemented-vs-catalog-tools)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Security Model](#security-model)
- [Lab Environments](#lab-environments)
- [Testing](#testing)
- [Verified Walkthrough](#verified-walkthrough)
- [Known Limitations](#known-limitations)
- [Repository Layout](#repository-layout)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Implemented vs. Catalog Tools

Every entry in `toolkit list-tools <module>` carries a `status` field. **Implemented**
means the module calls a real local binary, API, or Python logic and returns real
findings. **Catalog-only** means the tool is listed for domain coverage but requires
a vendor account ToolKit will never embed credentials for.

| Domain | Implemented | Catalog-only (requires vendor account) |
|---|---|---|
| SOC | Splunk, Wazuh | Microsoft Sentinel, IBM QRadar, Elastic SIEM |
| EDR | Wazuh *(shares the SOC backend)* | CrowdStrike, SentinelOne, Microsoft Defender |
| NetSec | nmap | Palo Alto, Fortinet, Cisco, OPNsense |
| AppSec | OWASP ZAP | Burp Suite, Nuclei, Postman |
| CloudSec | IaC Auditor | AWS GuardDuty, AWS Security Hub, Prisma Cloud, Mandiant |
| VM | Trivy | Tenable (Nessus), Qualys, Rapid7, OpenVAS |
| AISec | LLM Risk Scanner | Darktrace, Vectra |

Implemented tools, what each actually does, and how to run them:

| Tool | What it does | Needs |
|---|---|---|
| **Splunk** | Deploys Splunk Enterprise (Docker/local/AWS/Kubernetes), runs MITRE ATT&CK event simulations delivered via HTTP Event Collector | Docker, or your own AWS/kubeconfig credentials for cloud paths |
| **Wazuh** | Deploys the Wazuh manager/indexer/dashboard stack via Docker Compose, reports live container health | Docker |
| **OWASP ZAP** | Deploys a local ZAP daemon, drives its REST API to spider + actively scan a target | Docker |
| **nmap** | Wraps the `nmap` binary, parses real XML output into findings | `nmap` installed locally |
| **Trivy** | Wraps the `trivy` binary (`fs` or `image` mode), parses real JSON CVE output | `trivy` installed locally |
| **IaC Auditor** | Pure-Python static scanner for `.tf` and `docker-compose.yml` — public ingress on sensitive ports, hardcoded secrets, privileged containers, exposed Docker sockets | Nothing — zero dependencies, zero network access |
| **LLM Risk Scanner** | Pure-Python heuristic scanner for OWASP LLM Top 10-style patterns (prompt injection, insecure output handling, sensitive data exposure) in transcript/log files | Nothing — zero dependencies, zero network access |

The IaC Auditor and LLM Risk Scanner are regex/rule-based pattern matchers, not
trained classifiers — they're a fast first pass over text, not a certification of
safety. Every finding should be reviewed manually.

## Architecture

```
toolkit/cli.py          ← click command group (version, status, list-tools)
  ├── toolkit/deploy.py  ← `toolkit deploy <module> <tool>`
  ├── toolkit/scan.py    ← `toolkit scan <module> <tool>` (--simulate for attack sims)
  ├── toolkit/report.py  ← `toolkit report <module> <tool>`
  └── toolkit/open_dashboard.py  ← `toolkit open <module> <tool>`
        │
        ▼
  toolkit/core.py (ToolKitCore)
    - dynamically imports modules.<DOMAIN>.<tool>.<operation>
    - every operation module exposes execute(**kwargs) -> bool
        │
        ▼
  modules/<DOMAIN>/<tool>/
    config.py    ← settings + validate()
    deploy.py    ← for tools with a deployable backend
    scan.py       } one or more operations, each calling
    simulate.py   } toolkit.state.save_result() on completion
    report.py    ← thin wrapper: load_latest_result() + render_report()
        │
        ▼
  Shared infrastructure (toolkit/):
    security.py   ← require_authorized_target() — blocks active scans/sims
                    against anything outside RFC1918 + loopback unless
                    --i-have-authorization is passed
    state.py      ← persists every run's result to .toolkit_state/*.json
    reporting.py  ← renders persisted state into HTML or Markdown
```

Each module directory has its own `README.md` with full configuration and usage
details — see [Repository Layout](#repository-layout).

**Why Wazuh is listed under both SOC and EDR:** Wazuh is genuinely both a SIEM and an
endpoint agent manager. `modules/EDR/wazuh/` re-exports the single
`modules/SOC/wazuh/` implementation rather than duplicating it — see
[modules/EDR/wazuh/README.md](modules/EDR/wazuh/README.md).

## Installation

```bash
git clone https://github.com/imharshitaa/toolkit.git
cd toolkit
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

Verify the install:

```bash
toolkit --version
toolkit status           # checks for docker, terraform, kubectl, ansible, aws-cli
toolkit list-tools soc   # shows Splunk (implemented) + catalog entries
```

Per-tool binaries (install only what you plan to use):

| Tool | Install |
|---|---|
| Docker (Splunk, Wazuh, ZAP) | https://docs.docker.com/get-docker/ |
| nmap | `brew install nmap` / `apt install nmap` |
| Trivy | `brew install trivy` / https://trivy.dev |

IaC Auditor and LLM Risk Scanner need nothing beyond the base `pip install -e .`.

## Usage

```bash
toolkit deploy <module> <tool> [--environment docker|local|aws|kubernetes] [--dry-run]
toolkit scan   <module> <tool> --target <target> [--scan-type quick|full|stealth] [--simulate]
toolkit report <module> <tool> [--format html|markdown] [--severity-filter high]
toolkit open   <module> <tool>
```

Examples:

```bash
# Static scans — no deploy step, no credentials
toolkit scan cloudsec iacauditor --target labs/
toolkit scan aisec llmriskscanner --target /path/to/transcript.log

# Local binary wrappers — need nmap/trivy installed
toolkit scan netsec nmap --target 192.168.1.0/24 --scan-type quick
toolkit scan vm trivy --target . --scan-type full

# Dockerized services — need Docker
toolkit deploy appsec zap
toolkit scan appsec zap --target http://localhost:8081   # e.g. the DVWA lab target
toolkit deploy soc wazuh
toolkit scan soc wazuh                                    # health check, not a fresh deploy

# Attack simulation (generates synthetic MITRE ATT&CK events)
toolkit deploy soc splunk
toolkit scan soc splunk --target localhost:8088 --simulate --scenario brute_force

# Reports are built from the most recent real result for that tool
toolkit report cloudsec iacauditor --format markdown
```

Targets outside RFC1918/loopback ranges are rejected by default on every active
scan/simulate — pass `--i-have-authorization` only for systems you own or are
explicitly authorized to test (see [Security Model](#security-model)).

## Security Model

- **No embedded credentials, anywhere.** AWS/Azure/GCP credentials are read strictly
  from environment variables / the standard credential chain
  (`toolkit/utils.py::get_cloud_credentials`) — never hardcoded, never stored by
  ToolKit. AWS/Kubernetes deploys use *your own* `boto3`/`kubectl` credential chain,
  exactly like the AWS CLI or `kubectl` itself.
- **Target authorization guardrail.** `toolkit/security.py::require_authorized_target`
  blocks nmap/ZAP/Trivy-image scans and Splunk attack simulations against anything
  outside loopback + RFC1918 private ranges unless `--i-have-authorization` is passed
  explicitly — and even then it logs a loud warning. Only test systems you own or
  hold written permission to assess.
- **No hardcoded lab secrets.** `labs/docker/docker-compose.yml` and
  `labs/terraform/aws_lab.tf` require every password/token/CIDR as an explicit
  input (`${VAR:?}` in Compose, no-default Terraform variables) — there is no
  built-in `admin/admin` anywhere in this repo.
- **Results aren't fabricated.** `toolkit report` reads the real JSON result of the
  most recent `scan`/`simulate`/`deploy` from `.toolkit_state/` (gitignored). If
  nothing has been run yet, it fails with a clear error instead of generating a
  placeholder report.
- **Untrusted tool output.** ZAP/nmap/Trivy output is parsed defensively (missing
  fields default to safe placeholders); subprocess calls have explicit timeouts and
  handle non-zero exit codes and missing binaries without crashing.
- **Heuristic scanners are labeled as heuristic.** The IaC Auditor and LLM Risk
  Scanner are documented as pattern matching, not certified detection — both their
  `config.py` docstrings and this README say so explicitly.

## Lab Environments

- [`labs/docker/`](labs/docker/README.md) — Docker Compose stack for Splunk, ZAP,
  Wazuh (manager + indexer + dashboard), and DVWA as a safe local scan target.
- [`labs/terraform/`](labs/terraform/README.md) — standalone Terraform for a
  single-instance Splunk deployment on AWS, plus GuardDuty/CloudTrail, with no
  default admin CIDR or password.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

**Actual result at last verification: 102 passed, 0 failed, 0 skipped.**

What's covered and how — see [`tests/README.md`](tests/README.md) for the full
breakdown, including what requires Docker/live binaries and isn't exercised by the
unit suite (full Splunk/Wazuh Docker Compose stacks, live AWS/Kubernetes deploys).

## Verified Walkthrough

Run end-to-end against this repo's own `labs/` directory — no deploy step, no
external binary, no network access required:

```bash
$ toolkit scan cloudsec iacauditor --target labs/
Scanned 2 file(s), 0 finding(s)
✓ Scan completed successfully!

$ toolkit report cloudsec iacauditor --format markdown
Report saved to: reports/iacauditor_security_report_<timestamp>.md
```

Zero findings here is the expected, correct result — `labs/docker/docker-compose.yml`
and `labs/terraform/aws_lab.tf` were themselves fixed as part of this project to
remove the public ingress rules and hardcoded secrets the auditor is built to catch
(verified separately against an unfixed copy, which the auditor correctly flagged
for `0.0.0.0/0` SSH ingress and a hardcoded `admin_password`).

For the Dockerized tools (ZAP, Splunk, Wazuh), see the exact commands in
[Usage](#usage) and the per-module READMEs — live execution requires Docker, which
is not available in every development environment (see
[Known Limitations](#known-limitations)).

## Known Limitations

Documented explicitly rather than silently skipped:

- **nmap and Trivy binaries**: not installed in every environment. Unit tests mock
  `subprocess`/`shutil.which`; the actual binary output format is covered by the
  parser tests (`tests/test_nmap.py`, `tests/test_trivy.py`), not a live scan.
- **Docker-dependent live deploys** (ZAP daemon, Wazuh stack, Splunk Docker
  deployment): require a working Docker daemon. In some environments (including
  this project's primary development environment) Docker Desktop requires an
  organizational sign-in that isn't available, so these paths are covered by
  mocked integration tests (`tests/test_wazuh_deploy.py`, Docker SDK mocked), not
  a live run. The code path itself is exercised; the live container lifecycle is
  not.
- **Full Splunk/Wazuh stacks**: multi-GB images, slow to bring up even when Docker
  is available — covered by dry-run + mocked tests, not a live full-stack
  deployment in CI.
- **Live AWS/Kubernetes deploys**: require the operator's own cloud/cluster
  credentials, which this project does not have or store. The `deploy_aws`/
  `deploy_kubernetes` code paths are present and readable in
  `modules/SOC/splunk/deploy.py`, but not exercised against a real account here.
- **`toolkit scan --output`**: the CLI accepts this flag, but no module currently
  writes raw results to it — every module persists its structured result via
  `toolkit/state.py` regardless, which is what `toolkit report` actually reads.
  Use `toolkit report` to get output, not `scan --output`.

## Repository Layout

```
toolkit/                  Core CLI and shared infrastructure (see architecture above)
modules/
  SOC/splunk/              modules/SOC/splunk/README.md
  SOC/wazuh/               modules/SOC/wazuh/README.md
  EDR/wazuh/               modules/EDR/wazuh/README.md   (delegates to SOC/wazuh)
  NETSEC/nmap/             modules/NETSEC/nmap/README.md
  APPSEC/zap/              modules/APPSEC/zap/README.md
  VM/trivy/                modules/VM/trivy/README.md
  CLOUDSEC/iacauditor/     modules/CLOUDSEC/iacauditor/README.md
  AISEC/llmriskscanner/    modules/AISEC/llmriskscanner/README.md
labs/
  docker/                  labs/docker/README.md    (local Compose lab)
  terraform/               labs/terraform/README.md (AWS Splunk lab)
tests/                     tests/README.md          (how to run, what's covered)
config.yaml                Global defaults (authorized networks, timeouts, reporting)
setup.py / requirements*.txt
```

Every directory listed above has its own `README.md` with configuration and usage
details scoped to that directory.

## Roadmap

Realistic near-term improvements, not aspirational claims:

1. **Wire `--output` through to each module** so raw JSON/XML tool output can be
   saved directly, not just the derived report (currently accepted by the CLI but
   unused — see [Known Limitations](#known-limitations)).
2. **CI pipeline** (GitHub Actions) running `pytest` on every push — there is
   currently no automated CI; tests are run manually.
3. **A real end-to-end live-Docker test** once run in an environment where Docker
   doesn't require organizational sign-in — deploy ZAP, scan DVWA, generate a
   report, assert on the real alert content rather than mocked data.

## Contributing

This is a personal portfolio project, not an actively maintained open-source
project seeking contributions. Issues and pull requests may not receive a response.
Feel free to fork it.

## License

MIT — see [LICENSE](LICENSE).
