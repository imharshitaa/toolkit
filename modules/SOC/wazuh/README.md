# Wazuh Module (SOC / EDR)

Deploys the Wazuh stack (manager, indexer, dashboard) via Docker Compose and
reports on its live container health.

Status: **implemented**.

This is the backend for both `toolkit <cmd> soc wazuh` and
`toolkit <cmd> edr wazuh` — Wazuh is genuinely both a SIEM and an endpoint-agent
manager, so rather than build two separate implementations, `modules/EDR/wazuh/`
re-exports this module's functions. See `modules/EDR/wazuh/README.md`.

## What ToolKit automates

| Command | What it does |
|---|---|
| `toolkit deploy soc wazuh` | Runs `docker compose -f labs/docker/docker-compose.yml --env-file labs/docker/.env up -d wazuh wazuh-indexer wazuh-dashboard`, then checks container health |
| `toolkit deploy soc wazuh --dry-run` | Logs the exact compose command without running it — Docker is never touched |
| `toolkit scan soc wazuh` | Inspects the three containers' live status via the Docker SDK, without redeploying anything |
| `toolkit report soc wazuh --format html\|markdown` | Renders a report from the most recent scan or deploy |

## Prerequisites

- Docker and Docker Compose
- `labs/docker/.env` populated — see `labs/docker/README.md` for required variables
  (`WAZUH_INDEXER_USERNAME`/`PASSWORD`, `WAZUH_API_USERNAME`/`PASSWORD`)

## Quick Start

```bash
cd labs/docker && cp .env.example .env   # edit with real values
cd ../..

toolkit deploy soc wazuh --dry-run   # verify config first
toolkit deploy soc wazuh
toolkit scan soc wazuh
toolkit report soc wazuh --format markdown

# Dashboard
# https://localhost:5601
```

## Configuration

`modules/SOC/wazuh/config.py`:
- `COMPOSE_FILE` / `ENV_FILE` point at `labs/docker/docker-compose.yml` and
  `labs/docker/.env` — this module operates on that exact compose file, it does
  not maintain a separate one.
- `SERVICES` — the three Compose service names brought up: `wazuh`,
  `wazuh-indexer`, `wazuh-dashboard`.
- `CONTAINER_NAMES` — maps each service to its actual container name
  (`wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`) for health lookups.
- `validate()` checks that both `COMPOSE_FILE` and `ENV_FILE` exist on disk before
  allowing a deploy to proceed.

## Health check states

`check_container_health()` (in `deploy.py`, shared by `scan.py`) reports one of:

| Status | Meaning |
|---|---|
| `running` | Container exists and Docker reports it running |
| `not_found` | Compose has not been brought up yet, or the container was removed |
| `unknown` | Docker daemon itself is unreachable (not installed, not running, no permission) |
| `error` | An unexpected Docker SDK error occurred — surfaced rather than swallowed |

`toolkit scan soc wazuh` returns non-zero (and the report marks affected services
`high` severity) unless every container reports `running`.

## Troubleshooting

**`unknown` status for every container**
Docker daemon isn't reachable. Run `docker ps` directly to confirm Docker itself is
up before troubleshooting ToolKit.

**`not_found` status for every container**
Nothing has been deployed yet — run `toolkit deploy soc wazuh`.

**Deploy succeeds but the dashboard won't load**
Wazuh's indexer can take a minute or two to finish initializing after the
containers report `running`; retry after a short wait.

## Known limitations

- The full stack is a multi-GB set of images and slow to start even where Docker
  works — this repo's automated tests cover config validation, the dry-run path,
  and the container-health state machine with the Docker SDK mocked
  (`tests/test_wazuh_deploy.py`), not a live multi-container bring-up.
- No agent enrollment automation — this module manages the central
  manager/indexer/dashboard stack, not individual endpoint agent installation.
