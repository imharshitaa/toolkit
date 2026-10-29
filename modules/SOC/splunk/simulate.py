"""
Splunk Attack Simulation
Generates synthetic security events aligned to MITRE ATT&CK techniques and
delivers them to a Splunk HTTP Event Collector. Falls back to a local JSON
event log when no HEC endpoint is reachable, so the simulation is useful even
without a running Splunk instance.
"""
import json
import random
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

from toolkit.security import UnauthorizedTargetError, require_authorized_target
from toolkit.state import save_result
from toolkit.utils import logger
from modules.SOC.splunk.config import DATA_INPUTS

EVENT_LOG_DIR = Path(".toolkit_state") / "events"

ATTACK_SCENARIOS = {
    'brute_force': {
        'technique_id': 'T1110',
        'technique_name': 'Brute Force',
        'tactic': 'Credential Access',
        'events': 50,
    },
    'lateral_movement': {
        'technique_id': 'T1021',
        'technique_name': 'Remote Services',
        'tactic': 'Lateral Movement',
        'events': 30,
    },
    'data_exfiltration': {
        'technique_id': 'T1048',
        'technique_name': 'Exfiltration Over Alternative Protocol',
        'tactic': 'Exfiltration',
        'events': 20,
    },
    'privilege_escalation': {
        'technique_id': 'T1078',
        'technique_name': 'Valid Accounts',
        'tactic': 'Privilege Escalation',
        'events': 15,
    },
    'persistence': {
        'technique_id': 'T1053',
        'technique_name': 'Scheduled Task/Job',
        'tactic': 'Persistence',
        'events': 10,
    },
}


def execute(**kwargs) -> bool:
    """
    Run attack simulation scenarios and deliver the generated events.

    Args:
        target: Splunk HEC host:port (default localhost:8088)
        scenario: scenario key from ATTACK_SCENARIOS, or 'all'
        allow_unsafe: set True (via --i-have-authorization) to target hosts
            outside private/loopback ranges

    Returns:
        bool: True if all requested scenarios ran (regardless of whether
            delivery went to Splunk or the local fallback log)
    """
    target = kwargs.get('target') or 'localhost:8088'
    scenario = kwargs.get('scenario', 'all')
    allow_unsafe = kwargs.get('allow_unsafe', False)

    try:
        require_authorized_target(target, allow_unsafe=allow_unsafe)
    except UnauthorizedTargetError as e:
        logger.error(str(e))
        return False

    if scenario == 'all':
        scenarios_to_run = list(ATTACK_SCENARIOS.keys())
    elif scenario in ATTACK_SCENARIOS:
        scenarios_to_run = [scenario]
    else:
        logger.error(f"Unknown scenario: {scenario}")
        return False

    logger.info("Starting Splunk attack simulation")

    findings = []
    delivery_summary = []
    total_events = 0

    for scenario_name in scenarios_to_run:
        logger.info(f"Simulating: {scenario_name}")
        events = generate_events(scenario_name)
        destination, location = deliver_events(events, target, scenario_name)
        total_events += len(events)
        delivery_summary.append(f"{scenario_name}: {len(events)} events -> {destination} ({location})")

        config = ATTACK_SCENARIOS[scenario_name]
        findings.append({
            'title': f"{config['technique_name']} ({config['technique_id']})",
            'description': (
                f"Simulated {len(events)} '{scenario_name}' events for tactic "
                f"'{config['tactic']}', delivered via {destination}."
            ),
            'severity': 'high' if scenario_name != 'brute_force' else 'medium',
        })

    logger.info(f"Simulation complete. Generated {total_events} events across {len(scenarios_to_run)} scenario(s)")

    save_result('soc', 'splunk', 'simulate', {
        'tool_name': 'Splunk Attack Simulation',
        'summary': (
            f"Ran {len(scenarios_to_run)} MITRE ATT&CK-aligned scenario(s) against {target}, "
            f"generating {total_events} synthetic events."
        ),
        'findings': findings,
        'recommendations': [
            'Review delivery destinations below — events logged locally mean the '
            'configured Splunk HEC endpoint was unreachable, not that detections fired.',
            *delivery_summary,
        ],
        'target': target,
        'total_events': total_events,
    })

    return True


def generate_events(scenario: str) -> List[Dict[str, Any]]:
    """Generate synthetic events for one scenario."""
    config = ATTACK_SCENARIOS[scenario]
    count = config['events']
    generators = {
        'brute_force': _brute_force_events,
        'lateral_movement': _lateral_movement_events,
        'data_exfiltration': _data_exfiltration_events,
        'privilege_escalation': _privilege_escalation_events,
        'persistence': _persistence_events,
    }
    return generators[scenario](count)


def _brute_force_events(count: int) -> List[Dict[str, Any]]:
    usernames = ['admin', 'root', 'user', 'administrator', 'service_account']
    source_ips = ['192.168.1.' + str(random.randint(100, 200)),
                  '10.0.0.' + str(random.randint(1, 50)),
                  '172.16.0.' + str(random.randint(1, 100))]
    return [{
        'timestamp': datetime.now().isoformat(),
        'event_type': 'authentication',
        'action': 'login_failed',
        'username': random.choice(usernames),
        'source_ip': random.choice(source_ips),
        'destination_ip': '192.168.1.10',
        'protocol': 'ssh',
        'mitre_technique': 'T1110',
        'severity': 'medium',
    } for _ in range(count)]


def _lateral_movement_events(count: int) -> List[Dict[str, Any]]:
    hosts = ['workstation-01', 'server-02', 'db-server', 'file-server']
    protocols = ['RDP', 'SMB', 'WinRM', 'SSH']
    return [{
        'timestamp': datetime.now().isoformat(),
        'event_type': 'network_connection',
        'action': 'connection_established',
        'source_host': random.choice(hosts),
        'destination_host': random.choice(hosts),
        'protocol': random.choice(protocols),
        'source_user': 'compromised_user',
        'mitre_technique': 'T1021',
        'severity': 'high',
    } for _ in range(count)]


def _data_exfiltration_events(count: int) -> List[Dict[str, Any]]:
    external_ips = ['8.8.8.8', '1.1.1.1', '23.45.67.89', '198.51.100.42']
    protocols = ['DNS', 'HTTP', 'FTP', 'HTTPS']
    return [{
        'timestamp': datetime.now().isoformat(),
        'event_type': 'network_traffic',
        'action': 'outbound_connection',
        'source_ip': '192.168.1.100',
        'destination_ip': random.choice(external_ips),
        'protocol': random.choice(protocols),
        'bytes_out': random.randint(1000000, 100000000),
        'mitre_technique': 'T1048',
        'severity': 'critical',
    } for _ in range(count)]


def _privilege_escalation_events(count: int) -> List[Dict[str, Any]]:
    techniques = ['sudo', 'setuid', 'token_impersonation', 'scheduled_task']
    return [{
        'timestamp': datetime.now().isoformat(),
        'event_type': 'process_creation',
        'action': 'privilege_escalation',
        'user': 'low_priv_user',
        'target_user': 'root',
        'technique': random.choice(techniques),
        'command': '/bin/bash -i',
        'mitre_technique': 'T1078',
        'severity': 'high',
    } for _ in range(count)]


def _persistence_events(count: int) -> List[Dict[str, Any]]:
    mechanisms = ['cron_job', 'systemd_service', 'registry_run_key', 'startup_script']
    return [{
        'timestamp': datetime.now().isoformat(),
        'event_type': 'persistence',
        'action': 'persistence_created',
        'mechanism': random.choice(mechanisms),
        'file_path': '/etc/cron.d/malicious_job',
        'user': 'attacker',
        'mitre_technique': 'T1053',
        'severity': 'high',
    } for _ in range(count)]


def deliver_events(events: List[Dict[str, Any]], target: str, scenario: str) -> Tuple[str, str]:
    """
    Attempt to deliver events to Splunk HEC; fall back to a local JSON log if
    the endpoint is unreachable or misconfigured.

    Returns:
        (destination, location) where destination is 'splunk_hec' or 'local_log'.
    """
    hec_token = DATA_INPUTS['http']['token']
    verify_ssl = DATA_INPUTS['http'].get('verify_ssl', True)

    if hec_token:
        hec_url = f"https://{target}/services/collector/event"
        if send_to_splunk_hec(events, hec_url, hec_token, verify=verify_ssl):
            return 'splunk_hec', hec_url
        logger.warning(f"Splunk HEC at {hec_url} unreachable or rejected events; falling back to local log")
    else:
        logger.warning("SPLUNK_HEC_TOKEN not set; writing events to local log instead of Splunk")

    log_path = write_local_event_log(events, scenario)
    return 'local_log', str(log_path)


def write_local_event_log(events: List[Dict[str, Any]], scenario: str) -> Path:
    """Persist generated events to a local JSON file as a safe fallback sink."""
    EVENT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = EVENT_LOG_DIR / f"splunk_simulate_{scenario}_{datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    with open(path, 'w') as f:
        json.dump(events, f, indent=2, default=str)
    return path


def send_to_splunk_hec(events: List[Dict], hec_url: str, hec_token: str, verify: bool = True) -> bool:
    """Send events to a Splunk HTTP Event Collector endpoint."""
    headers = {
        'Authorization': f'Splunk {hec_token}',
        'Content-Type': 'application/json',
    }

    try:
        for event in events:
            payload = {'event': event, 'sourcetype': 'toolkit:simulation', 'index': 'security'}
            response = requests.post(hec_url, headers=headers, json=payload, verify=verify, timeout=5)
            if response.status_code != 200:
                logger.warning(f"HEC rejected event (status {response.status_code})")
                return False
        return True
    except requests.exceptions.RequestException as e:
        logger.debug(f"HEC delivery failed: {e}")
        return False
