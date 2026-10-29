"""
Wazuh Configuration
Deployment settings for the open-source Wazuh SIEM/EDR stack, run locally via
the docker-compose lab environment in labs/docker/.
"""
import os
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parents[3]
COMPOSE_FILE = BASE_DIR / "labs" / "docker" / "docker-compose.yml"
ENV_FILE = BASE_DIR / "labs" / "docker" / ".env"

# The three services that make up a usable Wazuh stack in this lab.
SERVICES = ["wazuh", "wazuh-indexer", "wazuh-dashboard"]
CONTAINER_NAMES = {
    "wazuh": "wazuh-manager",
    "wazuh-indexer": "wazuh-indexer",
    "wazuh-dashboard": "wazuh-dashboard",
}

WAZUH_CONFIG = {
    "dashboard_port": 5601,
    "api_port": 55000,
    "agent_registration_port": 1514,
    "agent_comm_port": 1515,
}


def validate() -> bool:
    """Confirm the compose file and a populated .env exist before deploying."""
    from toolkit.utils import logger

    if not COMPOSE_FILE.exists():
        logger.error(f"docker-compose file not found: {COMPOSE_FILE}")
        return False

    if not ENV_FILE.exists():
        logger.error(
            f".env file not found at {ENV_FILE}. "
            "Copy labs/docker/.env.example to labs/docker/.env and set real values first."
        )
        return False

    return True


def get_config() -> Dict[str, Any]:
    return {
        "compose_file": str(COMPOSE_FILE),
        "env_file": str(ENV_FILE),
        "services": SERVICES,
        "wazuh": WAZUH_CONFIG,
    }
