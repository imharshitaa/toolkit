"""
Wazuh Health Scan
Checks the live status of a running Wazuh deployment without redeploying it.
"""
from toolkit.state import save_result
from toolkit.utils import logger
from modules.SOC.wazuh.deploy import check_container_health


def execute(**kwargs) -> bool:
    """Inspect the current health of the Wazuh container stack."""
    health = check_container_health()
    running = sum(1 for h in health if h['status'] == 'running')

    logger.info(f"Wazuh health check: {running}/{len(health)} containers running")
    for h in health:
        logger.info(f"  {h['container']}: {h['status']}")

    save_result('soc', 'wazuh', 'scan', {
        'tool_name': 'Wazuh Health Scan',
        'summary': f"{running}/{len(health)} Wazuh containers running at scan time.",
        'findings': [{
            'title': f"{h['service']} ({h['container']})",
            'description': f"Status: {h['status']}. {h.get('detail', '')}".strip(),
            'severity': 'info' if h['status'] == 'running' else 'high',
        } for h in health],
        'recommendations': [] if running == len(health) else [
            "Run 'toolkit deploy soc wazuh' to (re)start the stack."
        ],
    })

    return running == len(health)
