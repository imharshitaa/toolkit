"""
ToolKit Security Guardrails
Restricts active scans and attack simulations to explicitly authorized targets.
"""
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from toolkit.utils import logger

PRIVATE_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('::1/128'),
]


class UnauthorizedTargetError(Exception):
    """Raised when a scan or simulation target is outside the authorized scope."""


def _extract_host(target: str) -> Optional[str]:
    """Pull a bare host/IP out of an IP, URL, host:port, or CIDR string."""
    target = target.strip()
    if '://' in target:
        return urlparse(target).hostname

    host = target.split('/', 1)[0]  # drop CIDR suffix, if any
    if host.count(':') == 1:  # host:port, not IPv6
        host = host.split(':', 1)[0]
    return host or None


def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        pass

    if host.lower() == 'localhost':
        return True

    try:
        resolved = socket.gethostbyname(host)
        return any(ipaddress.ip_address(resolved) in net for net in PRIVATE_NETWORKS)
    except (socket.gaierror, ValueError, OSError):
        return False


def require_authorized_target(target: str, allow_unsafe: bool = False) -> None:
    """
    Enforce that active scans/simulations only run against authorized targets.

    By default, only loopback and RFC1918 private ranges are permitted. Anything
    else requires the caller to explicitly pass allow_unsafe=True (wired to the
    CLI's --i-have-authorization flag), which still logs a loud warning so this
    can't happen by accident.

    Raises:
        UnauthorizedTargetError: if the target is out of scope and not overridden.
    """
    host = _extract_host(target)
    if not host:
        raise UnauthorizedTargetError(f"Could not determine a host to authorize for target: {target!r}")

    if _is_private_host(host):
        return

    if not allow_unsafe:
        raise UnauthorizedTargetError(
            f"'{target}' is outside private/loopback ranges. Active scans and attack "
            "simulations must be restricted to targets you are explicitly authorized "
            "to test. Re-run with --i-have-authorization only if you own this target "
            "or hold written permission to test it."
        )

    logger.warning(
        f"Proceeding against '{target}', which is outside private/loopback ranges, "
        "because --i-have-authorization was set. Only test systems you are "
        "explicitly authorized to assess."
    )
