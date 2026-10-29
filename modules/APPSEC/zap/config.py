"""
OWASP ZAP Configuration
Web application security testing configuration
"""
import os
from pathlib import Path

# ZAP Configuration
ZAP_CONFIG = {
    'version': '2.14.0',
    'api_key': os.getenv('ZAP_API_KEY', 'toolkit-zap-key'),
    'host': 'localhost',
    'port': 8080,
    'proxy_port': 8090,
}

# Deployment Configuration
DEPLOYMENT_CONFIG = {
    'docker': {
        'image': 'owasp/zap2docker-stable',
        'container_name': 'zap-scanner',
        'ports': {
            '8080': '8080',
            '8090': '8090',
        },
        # Actual launch command is built at deploy time from ZAP_CONFIG['api_key']
        # (see deploy.py) so the configured key is always the one actually used.
    },
    'local': {
        'install_path': '/opt/zaproxy',
        'data_dir': '~/.ZAP',
    }
}

# Scan Configuration
SCAN_PROFILES = {
    'quick': {
        'attack_mode': 'standard',
        'max_depth': 2,
        'thread_per_host': 2,
        'delay_in_ms': 0,
    },
    'full': {
        'attack_mode': 'standard',
        'max_depth': 5,
        'thread_per_host': 5,
        'delay_in_ms': 0,
    },
    'stealth': {
        'attack_mode': 'standard',
        'max_depth': 3,
        'thread_per_host': 1,
        'delay_in_ms': 1000,
    }
}

# Scanner Policies
SCANNER_POLICY = {
    'strength': 'medium',  # low, medium, high, insane
    'threshold': 'medium',  # off, low, medium, high
    'scanners': {
        'xss': True,
        'sqli': True,
        'csrf': True,
        'path_traversal': True,
        'xxe': True,
        'ssrf': True,
        'rce': True,
    }
}

# Report Configuration
REPORT_CONFIG = {
    'formats': ['html', 'json', 'xml', 'markdown'],
    'include_passed': False,
    'include_false_positives': False,
    'risk_levels': ['High', 'Medium', 'Low', 'Informational'],
}

def validate(require_non_default_key: bool = False) -> bool:
    """
    Validate ZAP configuration before deploying a new daemon.

    Args:
        require_non_default_key: when True (live deploys), reject the
            'toolkit-zap-key' placeholder so a real deployment never uses it.
    """
    from toolkit.utils import logger, check_port_available

    if require_non_default_key and ZAP_CONFIG['api_key'] == 'toolkit-zap-key':
        logger.error(
            "Refusing to deploy with the default placeholder API key. "
            "Set the ZAP_API_KEY environment variable to a real value first."
        )
        return False

    if not check_port_available(ZAP_CONFIG['port']):
        logger.warning(f"Port {ZAP_CONFIG['port']} is already in use")
        return False

    return True

def get_config(environment: str = 'docker') -> dict:
    """Get configuration for specific environment"""
    return {
        'zap': ZAP_CONFIG,
        'deployment': DEPLOYMENT_CONFIG.get(environment, {}),
        'scan_profiles': SCAN_PROFILES,
        'scanner_policy': SCANNER_POLICY,
        'report': REPORT_CONFIG,
    }
