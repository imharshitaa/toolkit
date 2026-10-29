"""
Trivy Scan
Wraps the trivy CLI binary (filesystem or container image mode), parses its
JSON output into structured findings.
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from toolkit.security import UnauthorizedTargetError, require_authorized_target
from toolkit.state import save_result
from toolkit.utils import logger
from modules.VM.trivy.config import DEFAULT_TIMEOUT_SECONDS, MAX_FINDINGS, SEVERITY_PROFILES, TRIVY_BINARY


def execute(**kwargs) -> bool:
    """
    Args:
        target: filesystem path or container image reference to scan
        target_type: 'fs' or 'image' (auto-detected from target if omitted)
        scan_type: profile key from SEVERITY_PROFILES (controls severity floor)
        timeout: scan timeout in seconds
        allow_unsafe: set True (via --i-have-authorization) when target_type is
            'image' and the image reference points at a non-local registry

    Returns:
        bool: Success status
    """
    target = kwargs.get('target')
    scan_type = kwargs.get('scan_type', 'quick')
    timeout = kwargs.get('timeout') or DEFAULT_TIMEOUT_SECONDS
    allow_unsafe = kwargs.get('allow_unsafe', False)

    if not target:
        logger.error("A --target is required (a filesystem path or image reference)")
        return False

    if not shutil.which(TRIVY_BINARY):
        logger.error(
            "trivy is not installed or not on PATH. Install it "
            "(e.g. 'brew install trivy') to use this module."
        )
        return False

    target_type = kwargs.get('target_type') or ('fs' if os.path.exists(target) else 'image')

    if target_type == 'image':
        # Image references can point at a remote registry — apply the same
        # authorization guard used for network-reaching scans.
        try:
            require_authorized_target(target.split('@')[0].split(':')[0], allow_unsafe=allow_unsafe)
        except UnauthorizedTargetError as e:
            logger.error(str(e))
            return False

    severity = SEVERITY_PROFILES.get(scan_type, SEVERITY_PROFILES['quick'])

    with tempfile.TemporaryDirectory() as tmp_dir:
        json_path = Path(tmp_dir) / 'trivy.json'
        command = [
            TRIVY_BINARY, target_type, '--format', 'json', '--severity', severity,
            '--output', str(json_path), target,
        ]
        logger.info(f"Running: {' '.join(command)}")

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.error(f"trivy scan timed out after {timeout}s")
            return False
        except FileNotFoundError:
            logger.error("trivy binary not found")
            return False

        if result.returncode != 0:
            logger.error(f"trivy exited with code {result.returncode}: {result.stderr.strip()}")
            return False

        if not json_path.exists():
            logger.error("trivy did not produce output")
            return False

        try:
            report_data = json.loads(json_path.read_text())
        except json.JSONDecodeError:
            logger.error("Failed to parse trivy JSON output")
            return False

    findings, vuln_count = _parse_trivy_report(report_data)
    truncated = len(findings) > MAX_FINDINGS
    if truncated:
        logger.warning(f"{len(findings) - MAX_FINDINGS} additional finding(s) suppressed (showing top {MAX_FINDINGS})")
        findings = findings[:MAX_FINDINGS]

    logger.info(f"Scan complete: {vuln_count} vulnerabilit(y/ies) found across {target}")

    save_result('vm', 'trivy', 'scan', {
        'tool_name': 'Trivy Vulnerability Scan',
        'summary': f"Scanned {target} ({target_type}): {vuln_count} vulnerabilit(y/ies) at or above {severity}.",
        'findings': findings,
        'recommendations': [
            'Upgrade affected packages to the fixed version listed in each finding where available.',
            'Re-run with --scan-type full to include lower-severity findings.',
        ] if findings else [],
        'target': target,
    })

    return True


def _parse_trivy_report(report_data: dict):
    """Parse trivy JSON report into (findings, vulnerability_count)."""
    findings = []

    for result in report_data.get('Results', []) or []:
        target_name = result.get('Target', 'unknown')
        for vuln in result.get('Vulnerabilities', []) or []:
            severity = (vuln.get('Severity') or 'unknown').lower()
            pkg = vuln.get('PkgName', 'unknown')
            installed = vuln.get('InstalledVersion', 'unknown')
            fixed = vuln.get('FixedVersion', '')
            cve_id = vuln.get('VulnerabilityID', 'unknown')

            description = f"{pkg} {installed} in {target_name} is affected by {cve_id}."
            if fixed:
                description += f" Fixed in {fixed}."
            else:
                description += " No fix currently available."

            findings.append({
                'title': f"{cve_id} in {pkg}",
                'description': description,
                'severity': severity if severity in ('critical', 'high', 'medium', 'low') else 'info',
            })

    return findings, len(findings)
