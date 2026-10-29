"""EDR domain entry point for Wazuh — delegates to the shared SOC/wazuh backend."""
from modules.SOC.wazuh.report import execute  # noqa: F401
