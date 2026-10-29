# nmap Module (NetSec)

A thin, validated wrapper around the `nmap` binary — runs a real scan, parses its
XML output into structured findings.

Status: **implemented**.

## What ToolKit automates

| Command | What it does |
|---|---|
| `toolkit scan netsec nmap --target <host> --scan-type quick\|full\|stealth\|compliance\|custom` | Runs `nmap` with the flags for that profile, parses the XML result |
| `toolkit report netsec nmap --format html\|markdown` | Renders a report from the most recent scan |

There is no `deploy` operation for this module — nmap is a CLI tool you run
against a target, not a service you stand up.

## Prerequisites

- The `nmap` binary installed and on `PATH`. If it's missing, `scan.py` reports
  that clearly and stops — it does not fabricate scan results.

## Quick Start

```bash
toolkit scan netsec nmap --target 192.168.1.0/24 --scan-type quick
toolkit scan netsec nmap --target localhost --ports 22,80,443
toolkit report netsec nmap --format markdown
```

## Scan profiles

`modules/NETSEC/nmap/config.py::SCAN_PROFILES`:

| `--scan-type` | nmap flags | Notes |
|---|---|---|
| `quick` | `-T4 -F` | Fast scan of the top 100 ports |
| `full` | `-T4 -p- -sV` | All 65535 ports, service/version detection |
| `stealth` | `-sS -T2` | SYN scan, slow timing |
| `compliance` | same as `full` | Intentional fallback — no distinct compliance profile exists yet |
| `custom` | same as `full` | Intentional fallback — use `--ports` to narrow scope instead |

`--ports <list>` overrides the profile's port-related flags when given.

## Target authorization

Every scan goes through `toolkit/security.py::require_authorized_target()` —
private/loopback targets are allowed by default, anything else requires
`--i-have-authorization`. Port scanning a host you don't control or have written
permission to test is not something this flag is meant to enable.

## Output

`_parse_nmap_xml()` extracts only `open` ports on hosts reported `up`, with
severity hardcoded to `medium` for every finding (nmap doesn't itself assess
severity — that's a deliberate simplification, not a parsing bug).

## Troubleshooting

**"nmap is not installed" error**
Install nmap for your platform (`apt install nmap`, `brew install nmap`, etc.) —
ToolKit does not bundle or install it for you.

**Scan takes a long time / seems to hang**
`full` scans all 65535 ports with service detection — this is inherently slow on
large networks. Use `quick` or narrow with `--ports` for faster iteration.

## Known limitations

- This repo's automated tests mock `subprocess.run`/`shutil.which` and verify XML
  parsing against representative nmap output — they do not run nmap itself, since
  the binary isn't guaranteed to be present in every environment (confirmed
  absent in this project's development environment).
