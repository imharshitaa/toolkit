"""
OWASP ZAP Scan
Drives a local ZAP daemon via its REST API to spider and (for non-quick
profiles) actively scan a target, gated by toolkit.security authorization.
"""
import time
from typing import Any, Dict

import requests

from toolkit.security import UnauthorizedTargetError, require_authorized_target
from toolkit.state import save_result
from toolkit.utils import logger
from modules.APPSEC.zap.config import SCAN_PROFILES, ZAP_CONFIG

RISK_TO_SEVERITY = {
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Informational': 'info',
}

POLL_INTERVAL_SECONDS = 2
POLL_TIMEOUT_SECONDS = 600


def _zap_base_url() -> str:
    return f"http://{ZAP_CONFIG['host']}:{ZAP_CONFIG['port']}"


def _zap_get(path: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    params = dict(params or {})
    params['apikey'] = ZAP_CONFIG['api_key']
    response = requests.get(f"{_zap_base_url()}{path}", params=params, timeout=15)
    response.raise_for_status()
    return response.json()


def _wait_for(condition, label: str, timeout: int = POLL_TIMEOUT_SECONDS) -> None:
    start = time.time()
    while not condition():
        if time.time() - start > timeout:
            logger.warning(f"{label} did not finish within {timeout}s — proceeding with partial results")
            return
        time.sleep(POLL_INTERVAL_SECONDS)


def execute(**kwargs) -> bool:
    """
    Args:
        target: URL to scan (must be private/loopback unless allow_unsafe is set)
        scan_type: 'quick' (spider + passive only) or 'full'/'stealth'/'compliance'/'custom' (adds active scan)
        allow_unsafe: set True (via --i-have-authorization) to target hosts outside private/loopback ranges

    Returns:
        bool: Success status
    """
    target = kwargs.get('target')
    scan_type = kwargs.get('scan_type', 'quick')
    allow_unsafe = kwargs.get('allow_unsafe', False)

    if not target:
        logger.error("A --target URL is required")
        return False

    try:
        require_authorized_target(target, allow_unsafe=allow_unsafe)
    except UnauthorizedTargetError as e:
        logger.error(str(e))
        return False

    profile = SCAN_PROFILES.get(scan_type, SCAN_PROFILES['quick'])

    try:
        _zap_get('/JSON/core/view/version/')
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Could not reach ZAP daemon at {_zap_base_url()}: {e}. "
            "Run 'toolkit deploy appsec zap' first."
        )
        return False

    logger.info(f"Spidering {target}")
    spider_result = _zap_get('/JSON/spider/action/scan/', {'url': target, 'maxDepth': profile['max_depth']})
    scan_id = spider_result.get('scan')
    _wait_for(lambda: int(_zap_get('/JSON/spider/view/status/', {'scanId': scan_id})['status']) >= 100, "Spider")

    if scan_type != 'quick':
        logger.info(f"Running active scan against {target}")
        ascan_result = _zap_get('/JSON/ascan/action/scan/', {'url': target, 'recurse': 'true'})
        ascan_id = ascan_result.get('scan')
        _wait_for(lambda: int(_zap_get('/JSON/ascan/view/status/', {'scanId': ascan_id})['status']) >= 100,
                  "Active scan")

    alerts = _zap_get('/JSON/core/view/alerts/', {'baseurl': target}).get('alerts', [])
    findings = [{
        'title': alert.get('alert', 'Unknown finding'),
        'description': alert.get('description') or alert.get('solution', ''),
        'severity': RISK_TO_SEVERITY.get(alert.get('risk'), 'info'),
    } for alert in alerts]

    logger.info(f"Scan complete: {len(findings)} finding(s)")

    save_result('appsec', 'zap', 'scan', {
        'tool_name': 'OWASP ZAP Scan',
        'summary': (
            f"{'Spider + active scan' if scan_type != 'quick' else 'Spider (passive) scan'} "
            f"of {target} found {len(findings)} alert(s)."
        ),
        'findings': findings,
        'recommendations': sorted({a.get('solution') for a in alerts if a.get('solution')}),
        'target': target,
    })

    return True
