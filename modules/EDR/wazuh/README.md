# Wazuh Module (EDR)

This is a thin delegator, not a separate implementation.

```python
# modules/EDR/wazuh/deploy.py
from modules.SOC.wazuh.deploy import execute, check_container_health  # noqa: F401
```

`config.py`, `deploy.py`, `scan.py`, and `report.py` in this directory each
re-export the corresponding function from `modules/SOC/wazuh/`. Wazuh is
genuinely both a SIEM (SOC domain) and an endpoint-agent manager (EDR domain) —
rather than duplicate the deployment/health-check logic for two tool catalog
entries, `toolkit <cmd> edr wazuh` and `toolkit <cmd> soc wazuh` run the exact
same code against the exact same running stack.

**Full documentation lives in `modules/SOC/wazuh/README.md`** — commands,
configuration, health-check states, and troubleshooting are identical regardless
of which domain you invoke it through:

```bash
toolkit deploy edr wazuh      # identical to: toolkit deploy soc wazuh
toolkit scan edr wazuh        # identical to: toolkit scan soc wazuh
toolkit report edr wazuh      # identical to: toolkit report soc wazuh
```

Status: **implemented** (via delegation).
