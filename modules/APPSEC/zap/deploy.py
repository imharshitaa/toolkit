"""
OWASP ZAP Deployment
Runs a local, API-key-protected ZAP daemon via Docker.
"""
import docker

from toolkit.state import save_result
from toolkit.utils import logger
from modules.APPSEC.zap.config import DEPLOYMENT_CONFIG, ZAP_CONFIG, validate


def execute(**kwargs) -> bool:
    """
    Args:
        environment: only 'docker' is implemented
        dry_run: validate configuration without starting a container

    Returns:
        bool: Success status
    """
    environment = kwargs.get('environment', 'docker')
    dry_run = kwargs.get('dry_run', False)

    if environment != 'docker':
        logger.error(f"Unsupported environment for ZAP: {environment} (only 'docker' is implemented)")
        return False

    docker_config = DEPLOYMENT_CONFIG['docker']
    command = (
        f"zap.sh -daemon -host 0.0.0.0 -port 8080 "
        f"-config api.disablekey=false -config api.key={ZAP_CONFIG['api_key']}"
    )

    if dry_run:
        logger.info("DRY RUN MODE - Simulating ZAP deployment")
        logger.info(f"Would run container '{docker_config['container_name']}' from {docker_config['image']}")
        return True

    if not validate(require_non_default_key=True):
        return False

    status = 'unknown'
    try:
        client = docker.from_env()

        try:
            existing = client.containers.get(docker_config['container_name'])
            logger.warning(f"Container {docker_config['container_name']} already exists — removing it")
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass

        logger.info(f"Pulling image: {docker_config['image']}")
        client.images.pull(docker_config['image'])

        logger.info("Starting ZAP container")
        container = client.containers.run(
            docker_config['image'],
            name=docker_config['container_name'],
            command=command,
            ports=docker_config['ports'],
            detach=True,
            restart_policy={'Name': 'unless-stopped'},
        )

        container.reload()
        status = container.status
        success = status == 'running'

    except Exception as e:
        logger.error(f"ZAP deployment failed: {e}")
        success = False

    save_result('appsec', 'zap', 'deploy', {
        'tool_name': 'OWASP ZAP Deployment',
        'summary': f"ZAP daemon deployment {'succeeded' if success else 'failed'}.",
        'findings': [{
            'title': 'ZAP daemon container',
            'description': f"Status: {status}" if success else 'Container failed to start — see logs.',
            'severity': 'info' if success else 'high',
        }],
        'environment': environment,
    })

    if success:
        logger.info(f"✓ ZAP is running at http://localhost:{ZAP_CONFIG['port']}")

    return success
