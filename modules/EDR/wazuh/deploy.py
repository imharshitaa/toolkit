"""EDR domain entry point for Wazuh — delegates to the shared SOC/wazuh backend."""
from modules.SOC.wazuh.deploy import execute, check_container_health  # noqa: F401
