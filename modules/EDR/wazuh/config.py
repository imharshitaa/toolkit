"""
Wazuh is both a SIEM (SOC domain) and an endpoint agent manager (EDR domain) —
this module re-exports the single SOC/wazuh backend rather than duplicating it.
"""
from modules.SOC.wazuh.config import get_config, validate  # noqa: F401
