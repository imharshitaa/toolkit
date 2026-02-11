"""
CrowdStrike Falcon EDR Configuration
Supports: Local agent deployment + AWS/Azure cloud environments
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List


# ─── Deployment Targets ────────────────────────────────────────────────────────

DEPLOYMENT_TARGETS = {
    "local": {
        "description": "Local machine / on-prem agent",
        "agent_binary": "falcon-sensor",
        "supported_os": ["linux", "windows", "macos"],
        "requires_internet": True,
    },
    "aws": {
        "description": "AWS EC2 / Lambda cloud deployment",
        "method": "SSM Run Command or EC2 User Data",
        "region_default": "us-east-1",
        "ssm_document": "AWS-InstallApplication",
    },
    "azure": {
        "description": "Azure VM / AKS cloud deployment",
        "method": "Azure Custom Script Extension",
        "region_default": "eastus",
    },
    "docker": {
        "description": "Containerised lab environment",
        "note": "CrowdStrike Falcon does NOT support full kernel sensor in containers. Use Falcon Container Sensor.",
        "image": "falcon-sensor:latest",
    },
}


# ─── API / Auth Configuration ──────────────────────────────────────────────────

@dataclass
class CrowdStrikeConfig:
    """
    CrowdStrike Falcon API credentials and deployment settings.
    Reads from environment variables by default — never hardcode secrets.
    """

    # Falcon API credentials (OAuth2)
    client_id: str = field(default_factory=lambda: os.getenv("CS_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("CS_CLIENT_SECRET", ""))
    base_url: str = field(default_factory=lambda: os.getenv("CS_BASE_URL", "https://api.crowdstrike.com"))

    # Falcon Sensor install settings
    customer_id: str = field(default_factory=lambda: os.getenv("CS_CUSTOMER_ID", ""))
    install_token: Optional[str] = field(default_factory=lambda: os.getenv("CS_INSTALL_TOKEN", None))
    sensor_version: str = "latest"

    # Prevention policy
    prevention_policy: str = "platform_default"   # or use a named policy ID
    detection_mode: str = "Aggressive"            # Aggressive | Moderate | Cautious

    # Deployment target
    deployment_target: str = "local"              # local | aws | azure | docker

    # Cloud-specific
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    aws_ssm_target_tag: str = "crowdstrike-managed"

    # Alert / notification routing
    alert_email: Optional[str] = field(default_factory=lambda: os.getenv("CS_ALERT_EMAIL", None))
    siem_forwarding_enabled: bool = False
    siem_host: Optional[str] = None
    siem_port: int = 514

    # Logging
    log_path: str = "/var/log/toolkit/crowdstrike"
    log_level: str = "INFO"

    # Report output
    report_output_dir: str = "./reports/edr/crowdstrike"

    def validate(self) -> bool:
        """Raise ValueError if required credentials are missing."""
        missing = []
        if not self.client_id:
            missing.append("CS_CLIENT_ID")
        if not self.client_secret:
            missing.append("CS_CLIENT_SECRET")
        if not self.customer_id:
            missing.append("CS_CUSTOMER_ID")
        if missing:
            raise ValueError(
                f"Missing required CrowdStrike credentials: {', '.join(missing)}\n"
                f"Set them as environment variables before running."
            )
        return True

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id[:4] + "****" if self.client_id else "NOT SET",
            "base_url": self.base_url,
            "customer_id": self.customer_id[:4] + "****" if self.customer_id else "NOT SET",
            "sensor_version": self.sensor_version,
            "prevention_policy": self.prevention_policy,
            "detection_mode": self.detection_mode,
            "deployment_target": self.deployment_target,
            "siem_forwarding_enabled": self.siem_forwarding_enabled,
        }


# ─── Detection Categories ──────────────────────────────────────────────────────

DETECTION_CATEGORIES = {
    "process_injection":      {"severity": "critical", "mitre": "T1055"},
    "credential_dumping":     {"severity": "critical", "mitre": "T1003"},
    "lateral_movement":       {"severity": "high",     "mitre": "T1021"},
    "persistence":            {"severity": "high",     "mitre": "T1053"},
    "c2_communication":       {"severity": "critical", "mitre": "T1071"},
    "ransomware_behavior":    {"severity": "critical", "mitre": "T1486"},
    "privilege_escalation":   {"severity": "high",     "mitre": "T1068"},
    "defense_evasion":        {"severity": "medium",   "mitre": "T1562"},
    "discovery":              {"severity": "low",      "mitre": "T1082"},
    "exfiltration":           {"severity": "high",     "mitre": "T1041"},
}


# ─── RTR (Real-Time Response) Commands ────────────────────────────────────────

RTR_COMMANDS: List[dict] = [
    {"name": "ls",          "description": "List directory contents"},
    {"name": "ps",          "description": "List running processes"},
    {"name": "netstat",     "description": "Active network connections"},
    {"name": "reg query",   "description": "Query Windows registry key"},
    {"name": "get",         "description": "Retrieve a file from the host"},
    {"name": "put",         "description": "Push a file to the host"},
    {"name": "run",         "description": "Execute a script or binary"},
    {"name": "kill",        "description": "Terminate a process by PID"},
    {"name": "contain",     "description": "Network-contain a host"},
    {"name": "lift_containment", "description": "Lift host network containment"},
]


# ─── Default instance ─────────────────────────────────────────────────────────

default_config = CrowdStrikeConfig()
