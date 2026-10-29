# Trivy Module (Vulnerability Management)

A thin, validated wrapper around the `trivy` binary — scans a filesystem path or
a container image for known CVEs and parses the result into findings.

Status: **implemented**.

## What ToolKit automates

| Command | What it does |
|---|---|
| `toolkit scan vm trivy --target <path-or-image> --scan-type quick\|full\|stealth\|compliance\|custom` | Runs `trivy fs` or `trivy image` (auto-detected) with the severity filter for that profile, parses the JSON result |
| `toolkit report vm trivy --format html\|markdown` | Renders a report from the most recent scan |

There is no `deploy` operation — Trivy is a CLI scanner, not a long-running
service.

## Prerequisites

- The `trivy` binary installed and on `PATH`. If it's missing, `scan.py` reports
  that clearly and stops.

## Quick Start

```bash
toolkit scan vm trivy --target .                        # scans the local filesystem
toolkit scan vm trivy --target nginx:latest              # scans a container image
toolkit report vm trivy --format markdown
```

## Target type detection

`scan.py` checks whether `target` exists as a local path; if so it runs
`trivy fs`, otherwise it treats it as an image reference and runs `trivy image`.
For image targets, the registry hostname portion is passed through
`require_authorized_target()` — scanning a private registry you control on your
own network is allowed by default; scanning an arbitrary public registry requires
`--i-have-authorization` (in practice this mainly matters if you point Trivy at a
registry that requires network egress you haven't explicitly approved — public
registries like Docker Hub typically aren't a target authorization concern the
way live network hosts are, but the guardrail is applied uniformly).

## Severity profiles

`modules/VM/trivy/config.py::SEVERITY_PROFILES`:

| `--scan-type` | `--severity` passed to Trivy |
|---|---|
| `quick`, `stealth` | `CRITICAL,HIGH` |
| `full`, `compliance`, `custom` | `CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN` |

## Output

`_parse_trivy_report()` extracts `VulnerabilityID`, `PkgName`,
`InstalledVersion`, `FixedVersion`, and `Severity` per result, capped at
`MAX_FINDINGS = 200` findings per scan — if a target has more vulnerabilities
than that, the report explicitly notes the result was truncated rather than
silently dropping the rest.

## Troubleshooting

**"trivy is not installed" error**
Install Trivy (`brew install aquasecurity/trivy/trivy`, or see Trivy's own
install docs) — ToolKit does not bundle it.

**Image scan fails to pull**
Confirm you have network access to the registry and, for private registries,
that you're already authenticated (`docker login`) — Trivy reuses your existing
Docker credentials, ToolKit does not manage registry auth.

## Known limitations

- This repo's automated tests mock `subprocess.run`/`shutil.which` and verify
  JSON parsing against a representative Trivy report — they do not run Trivy
  itself, since the binary isn't guaranteed to be present in every environment
  (confirmed absent in this project's development environment).
