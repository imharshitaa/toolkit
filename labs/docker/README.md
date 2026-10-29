# Docker Lab

A `docker-compose.yml` stack that brings up every self-hosted backend ToolKit's
implemented modules talk to: Splunk, OWASP ZAP, Wazuh (manager + indexer +
dashboard), and DVWA as a safe local scan target. Everything runs on your machine —
none of this is a third-party SaaS account.

## Setup

```bash
cd labs/docker
cp .env.example .env
```

Edit `.env` and set a real value for every variable — there are no defaults baked
into `docker-compose.yml`. Each environment variable is referenced as
`${VAR:?Set VAR in your .env file}`, so `docker compose up` fails fast with a clear
message if anything is left unset, instead of silently starting with a weak or
missing credential.

| Variable | Used by |
|---|---|
| `SPLUNK_PASSWORD` | Splunk admin password |
| `SPLUNK_HEC_TOKEN` | Splunk HTTP Event Collector token (used by `toolkit scan soc splunk --simulate`) |
| `ZAP_API_KEY` | ZAP daemon's REST API key (must also be set as `ZAP_API_KEY` in your shell before running `toolkit deploy appsec zap`, since the Python config reads it from the environment too) |
| `WAZUH_INDEXER_USERNAME` / `WAZUH_INDEXER_PASSWORD` | Wazuh indexer (OpenSearch) auth |
| `WAZUH_API_USERNAME` / `WAZUH_API_PASSWORD` | Wazuh manager API auth, used by the dashboard |

## Bring up everything

```bash
docker compose up -d
```

Or bring up only what you need:

```bash
docker compose up -d splunk
docker compose up -d zap dvwa
docker compose up -d wazuh wazuh-indexer wazuh-dashboard
```

## Services and ports

| Service | Container | Ports | Purpose |
|---|---|---|---|
| `splunk` | `splunk-enterprise` | 8000 (Web UI), 8088 (HEC), 8089 (Management), 9997 (Receiver) | SOC module backend |
| `zap` | `zap-scanner` | 8080 (UI/API), 8090 (Proxy) | AppSec module backend |
| `wazuh` | `wazuh-manager` | 1514 (agent registration), 1515 (agent comm), 514/udp (syslog), 55000 (API) | SOC/EDR module backend |
| `wazuh-indexer` | `wazuh-indexer` | 9200 | Wazuh's OpenSearch-based storage |
| `wazuh-dashboard` | `wazuh-dashboard` | 5601 | Wazuh web UI |
| `dvwa` | `dvwa` | 8081 → 80 | Intentionally vulnerable web app — scan target for `toolkit scan appsec zap --target http://localhost:8081` |

All services share the `security-net` bridge network (`172.20.0.0/16`), so they can
reach each other by service name (e.g. Wazuh's dashboard reaches
`https://wazuh-indexer:9200` internally).

## Using with ToolKit

```bash
toolkit deploy appsec zap --dry-run     # validates config without starting anything
toolkit deploy appsec zap               # equivalent to the docker compose commands above, for ZAP only
toolkit scan appsec zap --target http://localhost:8081
toolkit report appsec zap

toolkit deploy soc wazuh                # brings up wazuh + wazuh-indexer + wazuh-dashboard via this compose file
toolkit scan soc wazuh                  # health check against the running containers
```

ToolKit's `deploy` modules call the Docker SDK directly (for ZAP and Splunk) or shell
out to `docker compose -f labs/docker/docker-compose.yml` (for Wazuh) — they operate
on this exact file, so changes here are picked up automatically.

## Tear down

```bash
docker compose down            # stop and remove containers, keep volumes
docker compose down -v         # also remove volumes (full reset, loses all data)
```

## Notes

- `dvwa` (Damn Vulnerable Web Application) is intentionally insecure by design —
  it exists solely as a safe, local, legal target for ZAP's active scanner. Never
  expose it outside your local Docker network.
- This stack is for local development and portfolio demonstration, not production
  deployment — there's no TLS termination, no persistent backup strategy beyond the
  named Docker volumes, and the Wazuh/Splunk configurations use their simplest
  single-node setups.
