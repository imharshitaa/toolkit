# OWASP ZAP Module (AppSec)

Deploys an OWASP ZAP daemon in Docker and drives it through its own REST API to
run a real spider + active scan against a web application.

Status: **implemented**.

## What ToolKit automates

| Command | What it does |
|---|---|
| `toolkit deploy appsec zap` | Removes any pre-existing ZAP container, pulls `owasp/zap2docker-stable`, and starts it as a daemon with the configured API key |
| `toolkit deploy appsec zap --dry-run` | Validates config without touching Docker |
| `toolkit scan appsec zap --target <url> --scan-type quick\|full\|stealth` | Spiders the target, then (for anything but `quick`) runs ZAP's active scanner, then pulls alerts |
| `toolkit report appsec zap --format html\|markdown` | Renders a report from the most recent scan |

## Prerequisites

- Docker (ZAP deployment is Docker-only — `deploy.py` rejects any other
  `environment` value)
- A target you are authorized to scan — see [Target authorization](#target-authorization)

## Quick Start

```bash
export ZAP_API_KEY="<a-value-you-choose>"   # must match labs/docker/.env's ZAP_API_KEY

toolkit deploy appsec zap
toolkit scan appsec zap --target http://localhost:8081   # DVWA from labs/docker
toolkit report appsec zap --format markdown
```

## Configuration

`modules/APPSEC/zap/config.py`:
- `ZAP_CONFIG['api_key']` reads `ZAP_API_KEY` from the environment, falling back
  to the placeholder `toolkit-zap-key`. `validate(require_non_default_key=True)`
  rejects that placeholder before a real scan is allowed to proceed.
- `SCAN_PROFILES` — `quick` (spider only, no active scan), `full`, and `stealth`
  (slower request rate: higher `delay_in_ms`, lower `thread_per_host`) each map to
  a different `max_depth`/`thread_per_host`/`delay_in_ms` combination.

## Scan types

| `--scan-type` | Spider | Active scan | Use case |
|---|---|---|---|
| `quick` | Yes | No | Fast reconnaissance, passive findings only |
| `full` | Yes | Yes | Full active scan — sends real attack payloads |
| `stealth` | Yes | Yes (slower) | Active scan with throttled request rate |

**Active scanning sends real attack payloads to the target.** Only run `full` or
`stealth` against a target you are explicitly authorized to test.

## Target authorization

`require_authorized_target()` (`toolkit/security.py`) is enforced before any
scan runs. By default only loopback and RFC1918 private addresses are allowed.
To scan anything else:

```bash
toolkit scan appsec zap --target http://example-authorized-target.com --i-have-authorization
```

This flag exists for legitimately authorized external targets (e.g., a staging
environment on a public IP you control) — it is not a bypass for scanning
targets you don't have permission to test.

## Troubleshooting

**Scan fails immediately with a connection error**
Confirm the ZAP daemon is actually running and reachable: `docker ps` should show
the ZAP container, and `curl http://localhost:8080` should respond.

**Active scan times out without a result**
`_wait_for()` polls for 600 seconds and then logs a warning and proceeds with
whatever partial results are available, rather than hanging indefinitely — a
timeout means the target is slow or unreachable, not necessarily a bug.

## Known limitations

- This repo's automated tests mock `requests.get`/`post` against ZAP's REST API
  shape — they do not exercise a live ZAP daemon or Docker in CI. A live run
  (deploy → scan → report) needs to be verified manually wherever Docker is
  actually usable.
