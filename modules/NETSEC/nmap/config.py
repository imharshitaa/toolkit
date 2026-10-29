"""
nmap Configuration
Thin wrapper configuration around the nmap CLI binary for network scanning.
"""
import shutil

NMAP_BINARY = 'nmap'

# Maps the CLI's shared --scan-type choices onto real nmap flag sets.
# 'compliance' and 'custom' don't have a meaningful nmap-specific mode, so they
# fall back to the same flags as 'full' — this is documented, not hidden.
SCAN_PROFILES = {
    'quick': ['-T4', '-F'],
    'full': ['-T4', '-p-', '-sV'],
    'stealth': ['-sS', '-T2'],
    'compliance': ['-T4', '-p-', '-sV'],
    'custom': ['-T4', '-p-', '-sV'],
}

DEFAULT_TIMEOUT_SECONDS = 300


def validate() -> bool:
    """Confirm the nmap binary is installed."""
    from toolkit.utils import logger

    if not shutil.which(NMAP_BINARY):
        logger.error(
            "nmap is not installed or not on PATH. Install it "
            "(e.g. 'brew install nmap' or 'apt install nmap') to use this module."
        )
        return False
    return True


def get_config() -> dict:
    return {
        'binary': NMAP_BINARY,
        'scan_profiles': SCAN_PROFILES,
        'default_timeout': DEFAULT_TIMEOUT_SECONDS,
    }
