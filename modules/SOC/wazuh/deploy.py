"""
Wazuh Deployment
Brings up the Wazuh manager/indexer/dashboard services from the lab
docker-compose stack and reports real per-container health.
"""
from typing import Any, Dict

import docker

from toolkit.state import save_result
from toolkit.utils import logger, run_command
from modules.SOC.wazuh.config import CONTAINER_NAMES, COMPOSE_FILE, ENV_FILE, SERVICES, validate


def execute(**kwargs) -> bool:
    """
    Args:
        dry_run: validate configuration without starting containers

    Returns:
        bool: Success status

    Note: Wazuh in this toolkit is docker-only — it runs the lab's
    docker-compose stack rather than shelling out to Terraform/kubectl,
    since Wazuh ships no equivalent lightweight cloud/k8s path.
    """
    dry_run = kwargs.get('dry_run', False)

    if not validate():
        return False

    if dry_run:
        logger.info("DRY RUN MODE - Simulating Wazuh deployment")
        logger.info(f"Would run: docker compose -f {COMPOSE_FILE} --env-file {ENV_FILE} up -d {' '.join(SERVICES)}")
        return True

    logger.info("Starting Wazuh stack via docker compose")
    success, output = run_command([
        'docker', 'compose',
        '-f', str(COMPOSE_FILE),
        '--env-file', str(ENV_FILE),
        'up', '-d',
        *SERVICES,
    ])

    if not success:
        logger.error(f"docker compose failed: {output}")
        return False

    health = check_container_health()
    all_running = all(h['status'] == 'running' for h in health)

    if all_running:
        logger.info("✓ Wazuh stack is running")
        logger.info(f"Dashboard: https://localhost:5601 (username: admin)")
    else:
        logger.warning("Wazuh stack started but not all containers are healthy — see report for details")

    save_result('soc', 'wazuh', 'deploy', {
        'tool_name': 'Wazuh Deployment',
        'summary': f"Deployment {'succeeded' if all_running else 'completed with issues'} — "
                   f"{sum(1 for h in health if h['status'] == 'running')}/{len(health)} containers running.",
        'findings': [{
            'title': f"{h['service']} ({h['container']})",
            'description': f"Status: {h['status']}. {h.get('detail', '')}".strip(),
            'severity': 'info' if h['status'] == 'running' else 'high',
        } for h in health],
        'recommendations': [] if all_running else [
            'Run `docker compose -f labs/docker/docker-compose.yml logs <service>` to diagnose failing containers.'
        ],
    })

    return all_running


def check_container_health() -> list:
    """Inspect the real state of each Wazuh container via the Docker SDK."""
    results = []
    try:
        client = docker.from_env()
    except Exception as e:
        logger.error(f"Could not connect to Docker: {e}")
        return [{'service': s, 'container': CONTAINER_NAMES[s], 'status': 'unknown', 'detail': str(e)}
                for s in SERVICES]

    for service in SERVICES:
        container_name = CONTAINER_NAMES[service]
        try:
            container = client.containers.get(container_name)
            container.reload()
            results.append({
                'service': service,
                'container': container_name,
                'status': container.status,
                'detail': f"Started: {container.attrs.get('State', {}).get('StartedAt', 'unknown')}",
            })
        except docker.errors.NotFound:
            results.append({
                'service': service,
                'container': container_name,
                'status': 'not_found',
                'detail': 'Container does not exist — deployment may still be starting or failed.',
            })
        except Exception as e:
            results.append({
                'service': service,
                'container': container_name,
                'status': 'error',
                'detail': str(e),
            })

    return results
