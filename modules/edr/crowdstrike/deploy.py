"""
CrowdStrike Falcon EDR — Deployment Module
Supports: Linux/macOS local, AWS SSM, Docker (Falcon Container Sensor)

Usage (via CLI):
    toolkit deploy edr crowdstrike
    toolkit deploy edr crowdstrike --target aws
    toolkit deploy edr crowdstrike --target docker
"""

import os
import sys
import subprocess
import platform
import logging
from pathlib import Path
from typing import Optional

from .config import CrowdStrikeConfig, DEPLOYMENT_TARGETS, default_config

logger = logging.getLogger("toolkit.edr.crowdstrike.deploy")


# ─── Platform Detection ────────────────────────────────────────────────────────

def detect_platform() -> str:
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "macos"
    elif system == "windows":
        return "windows"
    else:
        raise RuntimeError(f"Unsupported OS: {system}")


# ─── Local Deployment ──────────────────────────────────────────────────────────

def deploy_local(config: CrowdStrikeConfig) -> bool:
    """
    Deploy the Falcon sensor on the local machine.
    Linux: .deb / .rpm package via package manager.
    macOS: .pkg installer.
    """
    os_type = detect_platform()
    logger.info(f"[CrowdStrike] Starting LOCAL deployment on {os_type.upper()}")

    config.validate()

    if os_type == "linux":
        return _deploy_linux(config)
    elif os_type == "macos":
        return _deploy_macos(config)
    elif os_type == "windows":
        return _deploy_windows(config)
    else:
        raise NotImplementedError(f"Local deploy not implemented for: {os_type}")


def _deploy_linux(config: CrowdStrikeConfig) -> bool:
    """Install Falcon sensor on Linux via deb/rpm."""
    installer_path = _locate_installer(".rpm") or _locate_installer(".deb")

    if not installer_path:
        logger.error(
            "[CrowdStrike] Sensor package not found.\n"
            "  Download it from: https://falcon.crowdstrike.com → Hosts → Sensor Downloads\n"
            "  Place the .rpm or .deb file in the current directory and re-run."
        )
        return False

    logger.info(f"[CrowdStrike] Installing sensor from: {installer_path}")

    # Detect package manager
    if installer_path.endswith(".rpm"):
        install_cmd = ["sudo", "rpm", "-ivh", "--nodeps", installer_path]
    else:
        install_cmd = ["sudo", "dpkg", "-i", installer_path]

    result = _run_command(install_cmd)
    if not result:
        return False

    # License the sensor with the Customer ID (CID)
    logger.info("[CrowdStrike] Licensing sensor with Customer ID (CID)...")
    cid_cmd = ["sudo", "/opt/CrowdStrike/falconctl", "-s", f"--cid={config.customer_id}"]
    if config.install_token:
        cid_cmd.append(f"--provisioning-token={config.install_token}")

    result = _run_command(cid_cmd)
    if not result:
        return False

    # Start the service
    logger.info("[CrowdStrike] Starting falcon-sensor service...")
    _run_command(["sudo", "systemctl", "start", "falcon-sensor"])
    _run_command(["sudo", "systemctl", "enable", "falcon-sensor"])

    logger.info("[CrowdStrike] ✅ Falcon sensor deployed and running on Linux.")
    _print_status_linux()
    return True


def _deploy_macos(config: CrowdStrikeConfig) -> bool:
    """Install Falcon sensor on macOS via .pkg installer."""
    installer_path = _locate_installer(".pkg")

    if not installer_path:
        logger.error(
            "[CrowdStrike] .pkg installer not found.\n"
            "  Download from Falcon console → Sensor Downloads."
        )
        return False

    logger.info(f"[CrowdStrike] Installing macOS pkg: {installer_path}")
    _run_command(["sudo", "installer", "-pkg", installer_path, "-target", "/"])

    logger.info("[CrowdStrike] Licensing sensor...")
    _run_command([
        "sudo", "/Applications/Falcon.app/Contents/Resources/falconctl",
        "license", config.customer_id
    ])

    logger.info("[CrowdStrike] ✅ Falcon sensor deployed on macOS.")
    return True


def _deploy_windows(config: CrowdStrikeConfig) -> bool:
    """Install Falcon sensor on Windows via .exe installer (PowerShell)."""
    installer_path = _locate_installer(".exe")
    if not installer_path:
        logger.error("[CrowdStrike] Windows installer (.exe) not found.")
        return False

    ps_cmd = (
        f'Start-Process -FilePath "{installer_path}" '
        f'-ArgumentList "/install", "/quiet", "/norestart", '
        f'"CID={config.customer_id}" -Wait'
    )
    result = subprocess.run(
        ["powershell", "-Command", ps_cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.error(f"[CrowdStrike] Windows install failed:\n{result.stderr}")
        return False

    logger.info("[CrowdStrike] ✅ Falcon sensor deployed on Windows.")
    return True


# ─── AWS Deployment (via SSM) ─────────────────────────────────────────────────

def deploy_aws(config: CrowdStrikeConfig, instance_ids: Optional[list] = None) -> bool:
    """
    Deploy the Falcon sensor to AWS EC2 instances using SSM Run Command.
    Requires: AWS CLI configured, IAM permissions for ssm:SendCommand.

    If instance_ids is None, targets all instances with the tag:
        crowdstrike-managed=true
    """
    try:
        import boto3
    except ImportError:
        logger.error("[CrowdStrike] boto3 not installed. Run: pip install boto3")
        return False

    config.validate()
    logger.info(f"[CrowdStrike] Starting AWS SSM deployment in {config.aws_region}")

    ssm = boto3.client("ssm", region_name=config.aws_region)
    ec2 = boto3.client("ec2", region_name=config.aws_region)

    # Resolve targets
    if not instance_ids:
        logger.info(f"[CrowdStrike] Resolving EC2 instances with tag: {config.aws_ssm_target_tag}=true")
        response = ec2.describe_instances(Filters=[
            {"Name": f"tag:{config.aws_ssm_target_tag}", "Values": ["true"]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ])
        instance_ids = [
            i["InstanceId"]
            for r in response["Reservations"]
            for i in r["Instances"]
        ]

    if not instance_ids:
        logger.warning("[CrowdStrike] No target EC2 instances found.")
        return False

    logger.info(f"[CrowdStrike] Targeting instances: {instance_ids}")

    # Install script — runs on each EC2 instance
    install_script = f"""
#!/bin/bash
set -e
echo "[toolkit] Downloading CrowdStrike Falcon sensor..."

# Download sensor from S3 or CrowdStrike API — update URL as needed
SENSOR_URL="${{CS_SENSOR_S3_URL:-https://your-s3-bucket/falcon-sensor.rpm}}"
curl -o /tmp/falcon-sensor.rpm "$SENSOR_URL"

echo "[toolkit] Installing sensor..."
rpm -ivh --nodeps /tmp/falcon-sensor.rpm

echo "[toolkit] Licensing sensor..."
/opt/CrowdStrike/falconctl -s --cid={config.customer_id}

echo "[toolkit] Starting service..."
systemctl start falcon-sensor
systemctl enable falcon-sensor

echo "[toolkit] Done."
/opt/CrowdStrike/falconctl -g --version
"""

    response = ssm.send_command(
        InstanceIds=instance_ids,
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [install_script]},
        Comment="CrowdStrike Falcon sensor deployment via toolkit",
        TimeoutSeconds=300,
    )

    command_id = response["Command"]["CommandId"]
    logger.info(f"[CrowdStrike] SSM Command sent. Command ID: {command_id}")
    logger.info(
        f"[CrowdStrike] Monitor progress:\n"
        f"  aws ssm list-command-invocations --command-id {command_id} --details"
    )
    return True


# ─── Docker Deployment (Falcon Container Sensor) ──────────────────────────────

def deploy_docker(config: CrowdStrikeConfig) -> bool:
    """
    Deploy CrowdStrike Falcon Container Sensor in a Docker/Kubernetes environment.
    Note: The full kernel sensor does NOT work inside containers.
    Uses Falcon Container Sensor (userspace) instead.
    """
    logger.info("[CrowdStrike] Deploying Falcon Container Sensor via Docker...")
    config.validate()

    compose_content = f"""version: "3.8"
services:
  falcon-container-sensor:
    image: registry.crowdstrike.com/falcon-container/us-1/release/falcon-sensor:latest
    container_name: falcon-container-sensor
    privileged: true
    pid: "host"
    network_mode: "host"
    environment:
      - FALCONCTL_OPT_CID={config.customer_id}
      - FALCONCTL_OPT_BACKEND=bpf
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /proc:/proc:ro
    restart: unless-stopped
"""

    compose_path = Path("./labs/docker/crowdstrike-compose.yml")
    compose_path.parent.mkdir(parents=True, exist_ok=True)
    compose_path.write_text(compose_content)

    logger.info(f"[CrowdStrike] Docker Compose written to: {compose_path}")
    logger.info("[CrowdStrike] Log in to CrowdStrike container registry first:")
    logger.info(
        "  docker login registry.crowdstrike.com "
        "-u <API_CLIENT_ID> -p <API_CLIENT_SECRET>"
    )

    result = _run_command(["docker-compose", "-f", str(compose_path), "up", "-d"])
    if result:
        logger.info("[CrowdStrike] ✅ Falcon Container Sensor running.")
    return result


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def deploy(target: str = "local", config: Optional[CrowdStrikeConfig] = None,
           instance_ids: Optional[list] = None) -> bool:
    """
    Main deploy dispatcher called by the CLI.

    Args:
        target: "local" | "aws" | "docker"
        config: CrowdStrikeConfig instance (uses default_config if None)
        instance_ids: Optional list of EC2 instance IDs (AWS only)
    """
    cfg = config or default_config

    if target not in DEPLOYMENT_TARGETS:
        logger.error(f"[CrowdStrike] Unknown target: '{target}'. "
                     f"Valid options: {list(DEPLOYMENT_TARGETS.keys())}")
        return False

    logger.info(f"[CrowdStrike] Deploying to target: {target.upper()}")
    logger.info(f"[CrowdStrike] Target info: {DEPLOYMENT_TARGETS[target]['description']}")

    dispatch = {
        "local":  lambda: deploy_local(cfg),
        "aws":    lambda: deploy_aws(cfg, instance_ids),
        "docker": lambda: deploy_docker(cfg),
        "azure":  lambda: _not_implemented("azure"),
    }

    return dispatch[target]()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _locate_installer(extension: str) -> Optional[str]:
    """Find installer file in current directory or /tmp."""
    for search_dir in [".", "/tmp"]:
        for f in Path(search_dir).glob(f"*{extension}"):
            return str(f)
    return None


def _run_command(cmd: list) -> bool:
    """Run a shell command, log output, return success bool."""
    logger.debug(f"[CrowdStrike] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            logger.info(result.stdout.strip())
        if result.stderr:
            logger.warning(result.stderr.strip())
        return result.returncode == 0
    except FileNotFoundError as e:
        logger.error(f"[CrowdStrike] Command not found: {e}")
        return False


def _print_status_linux():
    """Print sensor status after Linux install."""
    logger.info("[CrowdStrike] Sensor status:")
    _run_command(["sudo", "/opt/CrowdStrike/falconctl", "-g", "--version"])
    _run_command(["sudo", "systemctl", "status", "falcon-sensor", "--no-pager"])


def _not_implemented(target: str) -> bool:
    logger.error(f"[CrowdStrike] Deployment to '{target}' is not yet implemented.")
    return False
