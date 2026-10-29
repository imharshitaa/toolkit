"""
Trivy Configuration
Thin wrapper configuration around the Trivy CLI binary for filesystem and
container image vulnerability scanning.
"""
import shutil

TRIVY_BINARY = 'trivy'

# 'quick' reports only the severities most worth acting on immediately;
# 'full'/'compliance'/'custom' report everything Trivy finds.
SEVERITY_PROFILES = {
    'quick': 'CRITICAL,HIGH',
    'full': 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN',
    'stealth': 'CRITICAL,HIGH',
    'compliance': 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN',
    'custom': 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN',
}

DEFAULT_TIMEOUT_SECONDS = 300
MAX_FINDINGS = 200


def validate() -> bool:
    """Confirm the trivy binary is installed."""
    from toolkit.utils import logger

    if not shutil.which(TRIVY_BINARY):
        logger.error(
            "trivy is not installed or not on PATH. Install it "
            "(e.g. 'brew install trivy') to use this module."
        )
        return False
    return True


def get_config() -> dict:
    return {
        'binary': TRIVY_BINARY,
        'severity_profiles': SEVERITY_PROFILES,
        'default_timeout': DEFAULT_TIMEOUT_SECONDS,
    }
