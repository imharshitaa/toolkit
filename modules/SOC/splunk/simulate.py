"""
Splunk Attack Simulation Module
Generate test events and simulate security scenarios
"""
import random
import time
import json
import requests
from datetime import datetime
from typing import List, Dict, Any
from toolkit.utils import logger

# MITRE ATT&CK Techniques to simulate
ATTACK_SCENARIOS = {
    'brute_force': {
        'technique_id': 'T1110',
        'technique_name': 'Brute Force',
        'tactic': 'Credential Access',
        'events': 50
    },
    'lateral_movement': {
        'technique_id': 'T1021',
        'technique_name': 'Remote Services',
        'tactic': 'Lateral Movement',
        'events': 30
    },
    'data_exfiltration': {
        'technique_id': 'T1048',
        'technique_name': 'Exfiltration Over Alternative Protocol',
        'tactic': 'Exfiltration',
        'events': 20
    },
    'privilege_escalation': {
        'technique_id': 'T1078',
        'technique_name': 'Valid Accounts',
        'tactic': 'Privilege Escalation',
        'events': 15
    },
    'persistence': {
        'technique_id': 'T1053',
        'technique_name': 'Scheduled Task/Job',
        'tactic': 'Persistence',
        'events': 10
    }
}


def execute(**kwargs) -> bool:
    """
    Execute attack simulation
    
    Args:
        target: Splunk HEC endpoint
        simulate: Type of simulation (all scenarios run if True)
        scenario: Specific scenario to simulate
        
    Returns:
        bool: Success status
    """
    target = kwargs.get('target', 'localhost:8088')
    scenario = kwargs.get('scenario', 'all')
    
    logger.info("Starting Splunk attack simulation")
    
    # Determine which scenarios to run
    if scenario == 'all':
        scenarios_to_run = ATTACK_SCENARIOS.keys()
    else:
        scenarios_to_run = [scenario] if scenario in ATTACK_SCENARIOS else []
    
    if not scenarios_to_run:
        logger.error(f"Unknown scenario: {scenario}")
        return False
    
    # Run simulations
    total_events = 0
    for scenario_name in scenarios_to_run:
        logger.info(f"Simulating: {scenario_name}")
        events_count = simulate_scenario(scenario_name, target)
        total_events += events_count
        time.sleep(2)  # Delay between scenarios
    
    logger.info(f"✓ Simulation complete. Generated {total_events} events")
    return True


def simulate_scenario(scenario: str, target: str) -> int:
    """Simulate a specific attack scenario"""
    scenario_config = ATTACK_SCENARIOS.get(scenario)
    if not scenario_config:
        return 0
    
    events_generated = 0
    num_events = scenario_config['events']
    
    # Generate events based on scenario
    if scenario == 'brute_force':
        events_generated = simulate_brute_force(target, num_events)
    elif scenario == 'lateral_movement':
        events_generated = simulate_lateral_movement(target, num_events)
    elif scenario == 'data_exfiltration':
        events_generated = simulate_data_exfiltration(target, num_events)
    elif scenario == 'privilege_escalation':
        events_generated = simulate_privilege_escalation(target, num_events)
    elif scenario == 'persistence':
        events_generated = simulate_persistence(target, num_events)
    
    logger.info(f"  Generated {events_generated} {scenario} events")
    return events_generated


def simulate_brute_force(target: str, count: int) -> int:
    """Simulate brute force authentication attempts"""
    events = []
    
    usernames = ['admin', 'root', 'user', 'administrator', 'service_account']
    source_ips = [
        '192.168.1.' + str(random.randint(100, 200)),
        '10.0.0.' + str(random.randint(1, 50)),
        '172.16.0.' + str(random.randint(1, 100))
    ]
    
    for i in range(count):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'authentication',
            'action': 'login_failed',
            'username': random.choice(usernames),
            'source_ip': random.choice(source_ips),
            'destination_ip': '192.168.1.10',
            'protocol': 'ssh',
            'mitre_technique': 'T1110',
            'severity': 'medium'
        }
        events.append(event)
        time.sleep(0.1)
    
    # Send to Splunk (mock for now)
    logger.debug(f"Would send {len(events)} brute force events to {target}")
    return len(events)


def simulate_lateral_movement(target: str, count: int) -> int:
    """Simulate lateral movement across network"""
    events = []
    
    hosts = ['workstation-01', 'server-02', 'db-server', 'file-server']
    protocols = ['RDP', 'SMB', 'WinRM', 'SSH']
    
    for i in range(count):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'network_connection',
            'action': 'connection_established',
            'source_host': random.choice(hosts),
            'destination_host': random.choice([h for h in hosts]),
            'protocol': random.choice(protocols),
            'source_user': 'compromised_user',
            'mitre_technique': 'T1021',
            'severity': 'high'
        }
        events.append(event)
        time.sleep(0.1)
    
    logger.debug(f"Would send {len(events)} lateral movement events to {target}")
    return len(events)


def simulate_data_exfiltration(target: str, count: int) -> int:
    """Simulate data exfiltration attempts"""
    events = []
    
    external_ips = ['8.8.8.8', '1.1.1.1', '23.45.67.89', '198.51.100.42']
    protocols = ['DNS', 'HTTP', 'FTP', 'HTTPS']
    
    for i in range(count):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'network_traffic',
            'action': 'outbound_connection',
            'source_ip': '192.168.1.100',
            'destination_ip': random.choice(external_ips),
            'protocol': random.choice(protocols),
            'bytes_out': random.randint(1000000, 100000000),
            'mitre_technique': 'T1048',
            'severity': 'critical'
        }
        events.append(event)
        time.sleep(0.1)
    
    logger.debug(f"Would send {len(events)} exfiltration events to {target}")
    return len(events)


def simulate_privilege_escalation(target: str, count: int) -> int:
    """Simulate privilege escalation attempts"""
    events = []
    
    techniques = ['sudo', 'setuid', 'token_impersonation', 'scheduled_task']
    
    for i in range(count):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'process_creation',
            'action': 'privilege_escalation',
            'user': 'low_priv_user',
            'target_user': 'root',
            'technique': random.choice(techniques),
            'command': '/bin/bash -i',
            'mitre_technique': 'T1078',
            'severity': 'high'
        }
        events.append(event)
        time.sleep(0.1)
    
    logger.debug(f"Would send {len(events)} privilege escalation events to {target}")
    return len(events)


def simulate_persistence(target: str, count: int) -> int:
    """Simulate persistence mechanism creation"""
    events = []
    
    mechanisms = ['cron_job', 'systemd_service', 'registry_run_key', 'startup_script']
    
    for i in range(count):
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'persistence',
            'action': 'persistence_created',
            'mechanism': random.choice(mechanisms),
            'file_path': '/etc/cron.d/malicious_job',
            'user': 'attacker',
            'mitre_technique': 'T1053',
            'severity': 'high'
        }
        events.append(event)
        time.sleep(0.1)
    
    logger.debug(f"Would send {len(events)} persistence events to {target}")
    return len(events)


def send_to_splunk_hec(events: List[Dict], hec_url: str, hec_token: str) -> bool:
    """
    Send events to Splunk HTTP Event Collector
    
    Args:
        events: List of event dictionaries
        hec_url: Splunk HEC endpoint URL
        hec_token: HEC authentication token
        
    Returns:
        bool: Success status
    """
    headers = {
        'Authorization': f'Splunk {hec_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        for event in events:
            payload = {
                'event': event,
                'sourcetype': 'toolkit:simulation',
                'index': 'security'
            }
            
            response = requests.post(
                hec_url,
                headers=headers,
                json=payload,
                verify=False
            )
            
            if response.status_code != 200:
                logger.warning(f"Failed to send event: {response.text}")
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to send events to Splunk: {e}")
        return False
