"""
IaC Auditor Scan
Static rule-based scanner over Terraform (.tf) and Docker Compose files.
Looks for public ingress on sensitive ports, hardcoded secrets, privileged
containers, and exposed Docker sockets. Pure Python — no external binary.
"""
import re
from pathlib import Path

import yaml

from toolkit.state import save_result
from toolkit.utils import logger
from modules.CLOUDSEC.iacauditor.config import (
    COMPOSE_FILENAMES, PUBLIC_CIDR, SECRET_KEY_PATTERN, SENSITIVE_PORTS, TERRAFORM_GLOB,
)

INGRESS_BLOCK_RE = re.compile(r'ingress\s*\{([^{}]*)\}', re.DOTALL)
CIDR_RE = re.compile(r'cidr_blocks\s*=\s*\[([^\]]*)\]')
FROM_PORT_RE = re.compile(r'from_port\s*=\s*(\d+)')
TO_PORT_RE = re.compile(r'to_port\s*=\s*(\d+)')
DESCRIPTION_RE = re.compile(r'description\s*=\s*"([^"]*)"')
SECRET_RE = re.compile(r'([a-zA-Z0-9_]*' + SECRET_KEY_PATTERN + r'[a-zA-Z0-9_]*)\s*=\s*"([^"$]+)"', re.IGNORECASE)


def execute(**kwargs) -> bool:
    """
    Args:
        target: directory to scan for .tf and docker-compose.y*ml files
                (defaults to the current directory)

    Returns:
        bool: Success status
    """
    target = Path(kwargs.get('target', '.'))

    if not target.exists():
        logger.error(f"Target path does not exist: {target}")
        return False

    tf_files = sorted(target.rglob(TERRAFORM_GLOB))
    compose_files = [p for p in sorted(target.rglob('*')) if p.name in COMPOSE_FILENAMES]

    findings = []
    for tf_file in tf_files:
        findings.extend(_scan_terraform_file(tf_file))
    for compose_file in compose_files:
        findings.extend(_scan_compose_file(compose_file))

    files_scanned = len(tf_files) + len(compose_files)
    logger.info(f"Scanned {files_scanned} file(s), {len(findings)} finding(s)")

    save_result('cloudsec', 'iacauditor', 'scan', {
        'tool_name': 'IaC Auditor',
        'summary': f"Scanned {files_scanned} IaC file(s) under {target}: {len(findings)} finding(s).",
        'findings': findings,
        'recommendations': [
            'Restrict public ingress rules (0.0.0.0/0) to the specific CIDR ranges that need access.',
            'Move hardcoded secrets into environment variables or a secrets manager, never literal IaC values.',
            'Avoid privileged containers and host Docker socket mounts unless strictly required.',
        ] if findings else [],
        'target': str(target),
    })

    return True


def _scan_terraform_file(path: Path):
    findings = []
    text = path.read_text(errors='ignore')

    for match in INGRESS_BLOCK_RE.finditer(text):
        block = match.group(1)
        cidr_match = CIDR_RE.search(block)
        if not cidr_match or PUBLIC_CIDR not in cidr_match.group(1):
            continue

        from_port = FROM_PORT_RE.search(block)
        to_port = TO_PORT_RE.search(block)
        description = DESCRIPTION_RE.search(block)
        fp = int(from_port.group(1)) if from_port else None
        tp = int(to_port.group(1)) if to_port else fp
        label = description.group(1) if description else 'ingress rule'

        sensitive_hit = next((name for port, name in SENSITIVE_PORTS.items()
                               if fp is not None and fp <= port <= (tp or fp)), None)
        severity = 'critical' if sensitive_hit else 'medium'
        port_desc = f"port {fp}" if fp == tp else f"ports {fp}-{tp}"

        findings.append({
            'title': f"Public ingress on {port_desc} ({label})",
            'description': (
                f"{path}: security group rule allows {PUBLIC_CIDR} on {port_desc}"
                + (f", which exposes {sensitive_hit}" if sensitive_hit else "") + "."
            ),
            'severity': severity,
        })

    for match in SECRET_RE.finditer(text):
        key = match.group(1)
        findings.append({
            'title': f"Hardcoded secret value for '{key}'",
            'description': f"{path}: '{key}' is assigned a literal string instead of a variable reference.",
            'severity': 'high',
        })

    return findings


def _scan_compose_file(path: Path):
    findings = []
    try:
        data = yaml.safe_load(path.read_text(errors='ignore')) or {}
    except yaml.YAMLError:
        logger.warning(f"Could not parse {path} as YAML — skipping")
        return findings

    services = (data.get('services') or {}) if isinstance(data, dict) else {}
    for name, service in services.items():
        if not isinstance(service, dict):
            continue

        if service.get('privileged') is True:
            findings.append({
                'title': f"Privileged container: {name}",
                'description': f"{path}: service '{name}' runs with privileged: true, granting host-level access.",
                'severity': 'critical',
            })

        for volume in service.get('volumes', []) or []:
            if isinstance(volume, str) and '/var/run/docker.sock' in volume:
                findings.append({
                    'title': f"Docker socket exposed: {name}",
                    'description': f"{path}: service '{name}' mounts the host Docker socket, "
                                    "which grants effective root on the host.",
                    'severity': 'critical',
                })

        environment = service.get('environment')
        env_items = environment.items() if isinstance(environment, dict) else (
            (e.split('=', 1) for e in environment if isinstance(e, str) and '=' in e)
            if isinstance(environment, list) else []
        )
        for key, value in env_items:
            if re.search(SECRET_KEY_PATTERN, key, re.IGNORECASE) and isinstance(value, str) \
                    and value and not value.startswith('${'):
                findings.append({
                    'title': f"Hardcoded secret in compose service '{name}'",
                    'description': f"{path}: environment variable '{key}' has a literal value "
                                    "instead of a required ${VAR:?} reference.",
                    'severity': 'high',
                })

    return findings
