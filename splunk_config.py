"""
Splunk Configuration
Deployment and configuration settings for Splunk Enterprise
"""
import os
from pathlib import Path
from typing import Dict, Any

# Splunk Configuration
SPLUNK_CONFIG = {
    'version': '9.1.0',
    'admin_password': os.getenv('SPLUNK_PASSWORD', 'changeme'),
    'web_port': 8000,
    'mgmt_port': 8089,
    'splunkd_port': 9997,
    'license_file': os.getenv('SPLUNK_LICENSE_PATH', ''),
    'default_index': 'main',
}

# Deployment Configuration
DEPLOYMENT_CONFIG = {
    'docker': {
        'image': 'splunk/splunk:latest',
        'container_name': 'splunk-enterprise',
        'ports': {
            '8000': '8000',  # Web UI
            '8089': '8089',  # Management
            '9997': '9997',  # Receiver
        },
        'volumes': [
            './splunk-data/etc:/opt/splunk/etc',
            './splunk-data/var:/opt/splunk/var',
        ],
        'environment': {
            'SPLUNK_START_ARGS': '--accept-license',
            'SPLUNK_PASSWORD': SPLUNK_CONFIG['admin_password'],
        }
    },
    'aws': {
        'instance_type': 't3.xlarge',
        'ami': 'ami-0c55b159cbfafe1f0',  # Amazon Linux 2
        'disk_size': 100,  # GB
        'security_groups': ['splunk-sg'],
    },
    'kubernetes': {
        'namespace': 'security',
        'replicas': 1,
        'resources': {
            'requests': {
                'cpu': '2000m',
                'memory': '8Gi',
            },
            'limits': {
                'cpu': '4000m',
                'memory': '16Gi',
            }
        }
    }
}

# Index Configuration
INDEXES = [
    {
        'name': 'security',
        'maxDataSizeMB': 500000,
        'frozenTimePeriodInSecs': 2592000,  # 30 days
    },
    {
        'name': 'firewall',
        'maxDataSizeMB': 100000,
        'frozenTimePeriodInSecs': 1296000,  # 15 days
    },
    {
        'name': 'endpoint',
        'maxDataSizeMB': 200000,
        'frozenTimePeriodInSecs': 2592000,
    },
    {
        'name': 'cloudtrail',
        'maxDataSizeMB': 150000,
        'frozenTimePeriodInSecs': 5184000,  # 60 days
    }
]

# Data Input Configuration
DATA_INPUTS = {
    'tcp': {
        'port': 9997,
        'sourcetype': 'syslog',
        'index': 'main',
    },
    'syslog': {
        'port': 514,
        'sourcetype': 'syslog',
        'index': 'security',
    },
    'http': {
        'port': 8088,
        'token': os.getenv('SPLUNK_HEC_TOKEN', ''),
        'sourcetype': 'json',
    }
}

# Apps and Add-ons
APPS_TO_INSTALL = [
    'Splunk_TA_linux',
    'Splunk_TA_windows',
    'Splunk_TA_aws',
    'Splunk_TA_microsoft_azure',
    'Splunk_Security_Essentials',
    'Splunk_CIM',
]

# Search Optimization
SEARCH_CONFIG = {
    'max_concurrent_searches': 10,
    'max_search_time': 3600,  # 1 hour
    'ttl': 600,  # 10 minutes
}


def validate() -> bool:
    """Validate Splunk configuration"""
    from toolkit.utils import logger
    
    # Check password complexity
    if len(SPLUNK_CONFIG['admin_password']) < 8:
        logger.error("Admin password must be at least 8 characters")
        return False
    
    # Check license file if specified
    if SPLUNK_CONFIG['license_file']:
        license_path = Path(SPLUNK_CONFIG['license_file'])
        if not license_path.exists():
            logger.warning(f"License file not found: {license_path}")
    
    return True


def get_config(environment: str = 'docker') -> Dict[str, Any]:
    """Get configuration for specific environment"""
    return {
        'splunk': SPLUNK_CONFIG,
        'deployment': DEPLOYMENT_CONFIG.get(environment, {}),
        'indexes': INDEXES,
        'inputs': DATA_INPUTS,
        'apps': APPS_TO_INSTALL,
        'search': SEARCH_CONFIG,
    }
