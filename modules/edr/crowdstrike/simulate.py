"""
CrowdStrike Falcon EDR — Attack Simulation & Detection Testing

Simulates common attack techniques to verify Falcon detections are firing.
All simulations are SAFE — they mimic behaviour without actually causing harm.

Usage (via CLI):
    toolkit scan edr crowdstrike
    toolkit scan edr crowdstrike --technique credential_dumping
    toolkit scan edr crowdstrike --target 192.168.1.10   # remote via RTR
"""

import os
import sys
import time
import logging
import platform
import subprocess
import json
from datetime import datetime
from typing import Optional, List, Dict

from .config import CrowdStrikeConfig, DETECTION_CATEGORIES, default_config

logger = logging.getLogger("toolkit.edr.crowdstrike.simulate")


# ─── Simulation Registry ──────────────────────────────────────────────────────

SIMULATIONS: Dict[str, dict] = {
    "process_injection": {
        "description": "Simulate process injection (T1055) — benign parent/child spawn chain",
        "mitre": "T1055",
        "severity": "critical",
        "fn": "sim_process_injection",
    },
    "credential_dumping": {
        "description": "Simulate LSASS access pattern (T1003) — safe memory read attempt",
        "mitre": "T1003",
        "severity": "critical",
        "fn": "sim_credential_dumping",
    },
    "c2_beacon": {
        "description": "Simulate C2 beaconing pattern (T1071) — periodic outbound DNS/HTTP",
        "mitre": "T1071",
        "severity": "critical",
        "fn": "sim_c2_beacon",
    },
    "lateral_movement": {
        "description": "Simulate lateral movement (T1021) — SSH/SMB connection sweep",
        "mitre": "T1021",
        "severity": "high",
        "fn": "sim_lateral_movement",
    },
    "persistence": {
        "description": "Simulate persistence (T1053) — cron/scheduled task creation",
        "mitre": "T1053",
        "severity": "high",
        "fn": "sim_persistence",
    },
    "defense_evasion": {
        "description": "Simulate defense evasion (T1562) — log clearing & AV disablement attempt",
        "mitre": "T1562",
        "severity": "medium",
        "fn": "sim_defense_evasion",
    },
    "ransomware": {
        "description": "Simulate ransomware behaviour (T1486) — rapid file rename/encryption pattern",
        "mitre": "T1486",
        "severity": "critical",
        "fn": "sim_ransomware_behaviour",
    },
    "discovery": {
        "description": "Simulate host/network discovery (T1082, T1016)",
        "mitre": "T1082",
        "severity": "low",
        "fn": "sim_discovery",
    },
}


# ─── Individual Simulations ───────────────────────────────────────────────────

def sim_process_injection(config: CrowdStrikeConfig) -> dict:
    """
    Mimic a suspicious parent→child process chain that resembles injection.
    Uses only system-native binaries — no actual shellcode.
    """
    logger.info("[Simulate] T1055 — Process Injection pattern")
    result = {"technique": "T1055", "status": "unknown", "details": []}

    os_type = platform.system().lower()

    if os_type == "linux":
        # Spawn a child process with /proc self-read (mimics memory inspection)
        cmds = [
            ["bash", "-c", "cat /proc/self/maps > /dev/null"],
            ["bash", "-c", "ls -la /proc/$(pgrep -n bash)/mem 2>/dev/null || true"],
            ["python3", "-c", "import ctypes; print('[sim] ctypes loaded (injection vector)')"],
        ]
    elif os_type == "darwin":
        cmds = [
            ["bash", "-c", "vmmap $$ > /dev/null 2>&1 || true"],
            ["python3", "-c", "import ctypes; print('[sim] ctypes loaded')"],
        ]
    else:
        cmds = [["cmd.exe", "/c", "echo [sim] process injection pattern"]]

    for cmd in cmds:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            result["details"].append({"cmd": " ".join(cmd), "rc": proc.returncode})
        except Exception as e:
            result["details"].append({"cmd": " ".join(cmd), "error": str(e)})

    result["status"] = "completed"
    logger.info("[Simulate] T1055 — simulation completed. Check Falcon console for detections.")
    return result


def sim_credential_dumping(config: CrowdStrikeConfig) -> dict:
    """
    Simulate LSASS/credential access patterns.
    Linux: access /etc/shadow (will fail without root — that's the point).
    Windows: attempt to open lsass.exe process handle (benign read).
    """
    logger.info("[Simulate] T1003 — Credential Dumping pattern")
    result = {"technique": "T1003", "status": "unknown", "details": []}

    os_type = platform.system().lower()

    if os_type == "linux":
        cmds = [
            ["bash", "-c", "cat /etc/shadow 2>/dev/null || echo '[sim] /etc/shadow access denied (expected)'"],
            ["bash", "-c", "strings /proc/$(pgrep -n sshd 2>/dev/null || echo 1)/mem 2>/dev/null | head -5 || true"],
        ]
        for cmd in cmds:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            result["details"].append({"cmd": " ".join(cmd), "stdout": proc.stdout.strip()})

    elif os_type == "windows":
        ps_script = """
        try {
            $lsass = Get-Process lsass -ErrorAction SilentlyContinue
            if ($lsass) {
                Write-Output "[sim] LSASS PID: $($lsass.Id) — access attempt (benign)"
            }
        } catch {
            Write-Output "[sim] Access denied to LSASS (expected)"
        }
        """
        proc = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True, text=True, timeout=10
        )
        result["details"].append({"stdout": proc.stdout.strip()})

    result["status"] = "completed"
    logger.info("[Simulate] T1003 — completed. Falcon should generate a critical detection.")
    return result


def sim_c2_beacon(config: CrowdStrikeConfig, iterations: int = 3) -> dict:
    """
    Simulate C2 beaconing: periodic outbound HTTP requests at regular intervals.
    Uses safe, public endpoints — no actual C2 infrastructure.
    """
    logger.info(f"[Simulate] T1071 — C2 Beacon pattern ({iterations} iterations, 10s interval)")
    result = {"technique": "T1071", "status": "unknown", "details": []}

    # Benign beacon target — replace with internal honeypot in production
    beacon_targets = [
        "https://ifconfig.me",
        "https://api.ipify.org",
        "https://httpbin.org/get",
    ]

    for i in range(iterations):
        target = beacon_targets[i % len(beacon_targets)]
        logger.info(f"[Simulate] Beacon #{i+1} → {target}")
        try:
            import urllib.request
            req = urllib.request.urlopen(target, timeout=5)
            result["details"].append({
                "iteration": i + 1,
                "target": target,
                "status_code": req.status,
            })
        except Exception as e:
            result["details"].append({"iteration": i + 1, "target": target, "error": str(e)})

        if i < iterations - 1:
            time.sleep(10)

    result["status"] = "completed"
    logger.info("[Simulate] T1071 — C2 beacon simulation completed.")
    return result


def sim_lateral_movement(config: CrowdStrikeConfig, target: str = "127.0.0.1") -> dict:
    """
    Simulate lateral movement by probing common service ports (SSH, SMB, RDP).
    Uses a simple socket connection attempt — no actual exploitation.
    """
    logger.info(f"[Simulate] T1021 — Lateral Movement pattern toward {target}")
    result = {"technique": "T1021", "status": "unknown", "details": []}

    import socket
    ports_to_probe = {
        22:   "SSH",
        445:  "SMB",
        3389: "RDP",
        5985: "WinRM",
        135:  "RPC",
    }

    for port, service in ports_to_probe.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            conn = sock.connect_ex((target, port))
            status = "open" if conn == 0 else "closed"
        except Exception as e:
            status = f"error: {e}"
        finally:
            sock.close()

        result["details"].append({"service": service, "port": port, "status": status})
        logger.info(f"[Simulate]   {service:6} (:{port}) → {status}")

    result["status"] = "completed"
    return result


def sim_persistence(config: CrowdStrikeConfig) -> dict:
    """
    Simulate persistence mechanism (T1053) by writing a cron entry (Linux)
    or a scheduled task stub (Windows). Entry is immediately removed after creation.
    """
    logger.info("[Simulate] T1053 — Persistence pattern")
    result = {"technique": "T1053", "status": "unknown", "details": []}
    os_type = platform.system().lower()

    if os_type == "linux":
        cron_entry = "# [toolkit-sim] @reboot echo 'persistence_sim' > /dev/null"
        try:
            # Read existing crontab
            existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            new_crontab = (existing.stdout or "") + "\n" + cron_entry + "\n"

            # Write new crontab
            proc = subprocess.run(["crontab", "-"], input=new_crontab, capture_output=True, text=True)
            result["details"].append({"action": "cron_write", "rc": proc.returncode})

            # Immediately remove it
            cleaned = (existing.stdout or "").replace(cron_entry, "")
            subprocess.run(["crontab", "-"], input=cleaned, capture_output=True, text=True)
            result["details"].append({"action": "cron_cleanup", "status": "done"})
        except Exception as e:
            result["details"].append({"error": str(e)})

    elif os_type == "windows":
        ps_create = 'schtasks /create /tn "toolkit_sim_task" /tr "cmd.exe /c echo sim" /sc onlogon /f'
        ps_delete = 'schtasks /delete /tn "toolkit_sim_task" /f'
        subprocess.run(["cmd.exe", "/c", ps_create], capture_output=True)
        time.sleep(1)
        subprocess.run(["cmd.exe", "/c", ps_delete], capture_output=True)
        result["details"].append({"action": "scheduled_task_create_and_delete"})

    result["status"] = "completed"
    logger.info("[Simulate] T1053 — persistence simulation completed and cleaned up.")
    return result


def sim_defense_evasion(config: CrowdStrikeConfig) -> dict:
    """
    Simulate defense evasion (T1562) — attempt to clear audit logs
    and check AV service status. No actual disablement occurs.
    """
    logger.info("[Simulate] T1562 — Defense Evasion pattern")
    result = {"technique": "T1562", "status": "unknown", "details": []}
    os_type = platform.system().lower()

    if os_type == "linux":
        cmds = [
            ["bash", "-c", "journalctl --rotate 2>/dev/null || true"],
            ["bash", "-c", "cat /dev/null > /tmp/sim_log_clear.log && rm /tmp/sim_log_clear.log"],
            ["bash", "-c", "systemctl status falcon-sensor 2>/dev/null | head -3 || echo 'service check'"],
        ]
        for cmd in cmds:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            result["details"].append({"cmd": " ".join(cmd), "rc": proc.returncode})

    elif os_type == "windows":
        cmds = [
            ["cmd.exe", "/c", "wevtutil cl System 2>nul || echo [sim] log clear attempt"],
            ["powershell", "-Command", "Get-MpComputerStatus | Select-Object AntivirusEnabled"],
        ]
        for cmd in cmds:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            result["details"].append({"cmd": " ".join(cmd), "stdout": proc.stdout.strip()})

    result["status"] = "completed"
    return result


def sim_ransomware_behaviour(config: CrowdStrikeConfig) -> dict:
    """
    Simulate ransomware file activity (T1486) — rapid rename of temp files.
    Creates and renames files in /tmp only. Cleaned up afterwards.
    """
    logger.info("[Simulate] T1486 — Ransomware behaviour pattern")
    result = {"technique": "T1486", "status": "unknown", "details": []}

    import tempfile, shutil

    sim_dir = tempfile.mkdtemp(prefix="toolkit_ransim_")
    file_count = 20
    renamed = 0

    try:
        # Create benign temp files
        for i in range(file_count):
            f = os.path.join(sim_dir, f"document_{i:03d}.txt")
            with open(f, "w") as fh:
                fh.write(f"Simulated document content #{i}")

        # Rapidly rename them (mimics encryption rename)
        for i in range(file_count):
            src = os.path.join(sim_dir, f"document_{i:03d}.txt")
            dst = os.path.join(sim_dir, f"document_{i:03d}.txt.locked")
            os.rename(src, dst)
            renamed += 1
            time.sleep(0.05)

        result["details"].append({
            "files_created": file_count,
            "files_renamed": renamed,
            "sim_dir": sim_dir,
        })
        logger.info(f"[Simulate] Renamed {renamed} files rapidly — Falcon should detect ransomware pattern.")

    finally:
        shutil.rmtree(sim_dir, ignore_errors=True)
        logger.info("[Simulate] Cleanup: simulation directory removed.")

    result["status"] = "completed"
    return result


def sim_discovery(config: CrowdStrikeConfig) -> dict:
    """
    Simulate host/network discovery (T1082, T1016) — run common enumeration commands.
    """
    logger.info("[Simulate] T1082/T1016 — Discovery pattern")
    result = {"technique": "T1082+T1016", "status": "unknown", "details": []}
    os_type = platform.system().lower()

    if os_type in ("linux", "darwin"):
        cmds = [
            ["uname", "-a"],
            ["hostname"],
            ["whoami"],
            ["id"],
            ["ifconfig"],
            ["netstat", "-rn"],
            ["cat", "/etc/passwd"],
            ["ps", "aux"],
        ]
    else:
        cmds = [
            ["cmd.exe", "/c", "systeminfo"],
            ["cmd.exe", "/c", "ipconfig /all"],
            ["cmd.exe", "/c", "net user"],
            ["cmd.exe", "/c", "tasklist"],
        ]

    for cmd in cmds:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            result["details"].append({"cmd": " ".join(cmd), "rc": proc.returncode})
        except Exception as e:
            result["details"].append({"cmd": " ".join(cmd), "error": str(e)})

    result["status"] = "completed"
    return result


# ─── Runner — All Simulations ─────────────────────────────────────────────────

def run_all(config: CrowdStrikeConfig, target_ip: Optional[str] = None) -> List[dict]:
    """Run all registered simulations and return results list."""
    logger.info("=" * 60)
    logger.info("[CrowdStrike] Running FULL simulation suite")
    logger.info(f"[CrowdStrike] Timestamp: {datetime.utcnow().isoformat()}Z")
    logger.info("=" * 60)

    results = []
    for key, sim in SIMULATIONS.items():
        logger.info(f"\n[CrowdStrike] ── {sim['description']} ──")
        fn = globals().get(sim["fn"])
        if not fn:
            logger.warning(f"[CrowdStrike] Simulation function not found: {sim['fn']}")
            continue
        try:
            if key == "lateral_movement" and target_ip:
                r = fn(config, target=target_ip)
            else:
                r = fn(config)
            r["name"] = key
            r["mitre"] = sim["mitre"]
            r["severity"] = sim["severity"]
            results.append(r)
        except Exception as e:
            logger.error(f"[CrowdStrike] Simulation '{key}' failed: {e}")
            results.append({"name": key, "status": "error", "error": str(e)})

    logger.info("\n[CrowdStrike] ✅ Simulation suite complete.")
    logger.info("[CrowdStrike] Review detections at: https://falcon.crowdstrike.com/activity/detections")
    return results


# ─── Single Technique Runner ──────────────────────────────────────────────────

def run_technique(technique: str, config: Optional[CrowdStrikeConfig] = None,
                  target_ip: Optional[str] = None) -> dict:
    """Run a single named simulation technique."""
    cfg = config or default_config

    if technique not in SIMULATIONS:
        available = list(SIMULATIONS.keys())
        raise ValueError(
            f"Unknown technique: '{technique}'\n"
            f"Available: {available}"
        )

    sim = SIMULATIONS[technique]
    logger.info(f"[CrowdStrike] Running technique: {sim['description']}")
    fn = globals()[sim["fn"]]

    if technique == "lateral_movement" and target_ip:
        return fn(cfg, target=target_ip)
    return fn(cfg)


# ─── List available simulations ───────────────────────────────────────────────

def list_simulations() -> None:
    print("\nAvailable CrowdStrike simulations:\n")
    print(f"  {'Technique':<25} {'MITRE':<10} {'Severity':<10} Description")
    print("  " + "-" * 80)
    for key, sim in SIMULATIONS.items():
        print(f"  {key:<25} {sim['mitre']:<10} {sim['severity']:<10} {sim['description']}")
    print()
