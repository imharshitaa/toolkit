"""
nmap Scan
Wraps the nmap CLI binary, parses its XML output into structured findings, and
enforces target authorization before running.
"""
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from toolkit.security import UnauthorizedTargetError, require_authorized_target
from toolkit.state import save_result
from toolkit.utils import logger
from modules.NETSEC.nmap.config import DEFAULT_TIMEOUT_SECONDS, NMAP_BINARY, SCAN_PROFILES


def execute(**kwargs) -> bool:
    """
    Args:
        target: IP, hostname, or CIDR range to scan
        scan_type: profile key from SCAN_PROFILES
        ports: optional port range/list (e.g. '1-1000' or '22,80,443')
        timeout: scan timeout in seconds
        allow_unsafe: set True (via --i-have-authorization) to target hosts
            outside private/loopback ranges

    Returns:
        bool: Success status
    """
    target = kwargs.get('target')
    scan_type = kwargs.get('scan_type', 'quick')
    ports = kwargs.get('ports')
    timeout = kwargs.get('timeout') or DEFAULT_TIMEOUT_SECONDS
    allow_unsafe = kwargs.get('allow_unsafe', False)

    if not target:
        logger.error("A --target is required")
        return False

    if not shutil.which(NMAP_BINARY):
        logger.error(
            "nmap is not installed or not on PATH. Install it "
            "(e.g. 'brew install nmap' or 'apt install nmap') to use this module."
        )
        return False

    try:
        require_authorized_target(target, allow_unsafe=allow_unsafe)
    except UnauthorizedTargetError as e:
        logger.error(str(e))
        return False

    flags = list(SCAN_PROFILES.get(scan_type, SCAN_PROFILES['quick']))
    if ports:
        flags = [f for f in flags if f != '-F' and f != '-p-'] + ['-p', ports]

    with tempfile.TemporaryDirectory() as tmp_dir:
        xml_path = Path(tmp_dir) / 'scan.xml'
        command = [NMAP_BINARY, *flags, '-oX', str(xml_path), target]
        logger.info(f"Running: {' '.join(command)}")

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.error(f"nmap scan timed out after {timeout}s")
            return False
        except FileNotFoundError:
            logger.error("nmap binary not found")
            return False

        if result.returncode != 0:
            logger.error(f"nmap exited with code {result.returncode}: {result.stderr.strip()}")
            return False

        if not xml_path.exists():
            logger.error("nmap did not produce output — check target reachability")
            return False

        findings, host_count = _parse_nmap_xml(xml_path)

    logger.info(f"Scan complete: {host_count} host(s), {len(findings)} open port finding(s)")

    save_result('netsec', 'nmap', 'scan', {
        'tool_name': 'nmap Network Scan',
        'summary': f"Scanned {target} ({scan_type} profile): {host_count} host(s) up, {len(findings)} open port(s).",
        'findings': findings,
        'recommendations': [
            'Close or firewall any open ports that are not required for the service to function.',
            'Re-run with a more thorough profile (--scan-type full) for version-level detail.',
        ] if findings else [],
        'target': target,
    })

    return True


def _parse_nmap_xml(xml_path: Path):
    """Parse nmap XML output into (findings, host_count)."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    findings = []
    host_count = 0

    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        host_count += 1

        address_el = host.find('address')
        address = address_el.get('addr') if address_el is not None else 'unknown'

        ports_el = host.find('ports')
        if ports_el is None:
            continue

        for port in ports_el.findall('port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue

            service = port.find('service')
            service_name = service.get('name', 'unknown') if service is not None else 'unknown'
            product = service.get('product', '') if service is not None else ''
            version = service.get('version', '') if service is not None else ''

            description = f"Port {port.get('portid')}/{port.get('protocol')} open on {address} running {service_name}"
            if product:
                description += f" ({product} {version})".rstrip()

            findings.append({
                'title': f"Open port {port.get('portid')}/{port.get('protocol')} ({service_name})",
                'description': description,
                'severity': 'medium',
            })

    return findings, host_count
