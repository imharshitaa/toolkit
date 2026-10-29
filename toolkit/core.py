"""
ToolKit Core Engine
Central execution framework for all security tool operations
"""
import os
import sys
import importlib
from pathlib import Path
from typing import Dict, Any, Optional, List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
import yaml

console = Console()

class ToolKitCore:
    """Core execution engine for ToolKit operations"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.modules_path = self.base_path / "modules"
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load global configuration"""
        config_file = self.base_path / "config.yaml"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        return {}
    
    def get_module_path(self, module: str, tool: str) -> Path:
        """Get the path to a specific tool module"""
        module_map = {
            'soc': 'SOC',
            'edr': 'EDR',
            'netsec': 'NETSEC',
            'appsec': 'APPSEC',
            'cloudsec': 'CLOUDSEC',
            'vm': 'VM',
            'aisec': 'AISEC'
        }
        
        module_name = module_map.get(module.lower())
        if not module_name:
            raise ValueError(f"Unknown module: {module}")
        
        tool_path = self.modules_path / module_name / tool.lower()
        if not tool_path.exists():
            raise ValueError(f"Tool not found: {tool} in {module}")
        
        return tool_path
    
    def load_tool_module(self, module: str, tool: str, operation: str):
        """Dynamically load a tool's operation module"""
        try:
            module_path = f"modules.{module.upper()}.{tool.lower()}.{operation}"
            return importlib.import_module(module_path)
        except ImportError as e:
            console.print(f"[red]Error loading {operation} for {tool}: {e}[/red]")
            return None
    
    def execute_operation(self, module: str, tool: str, operation: str, **kwargs) -> bool:
        """Execute a specific operation on a tool"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"Executing {operation} for {tool}...", 
                    total=None
                )
                
                tool_module = self.load_tool_module(module, tool, operation)
                if not tool_module:
                    return False
                
                # Execute the operation
                if hasattr(tool_module, 'execute'):
                    result = tool_module.execute(**kwargs)
                    progress.update(task, completed=True)
                    return result
                else:
                    console.print(f"[red]No execute function found in {operation}[/red]")
                    return False
                    
        except Exception as e:
            console.print(f"[red]Execution failed: {e}[/red]")
            return False
    
    def validate_tool_config(self, module: str, tool: str) -> bool:
        """Validate tool configuration"""
        try:
            tool_path = self.get_module_path(module, tool)
            config_file = tool_path / "config.py"
            
            if not config_file.exists():
                console.print(f"[yellow]Warning: No config.py found for {tool}[/yellow]")
                return True
            
            # Import and validate config
            config_module = self.load_tool_module(module, tool, 'config')
            if hasattr(config_module, 'validate'):
                return config_module.validate()
            
            return True
            
        except Exception as e:
            console.print(f"[red]Configuration validation failed: {e}[/red]")
            return False


CATALOG_ONLY = 'catalog-only — requires vendor account'
IMPLEMENTED = 'implemented'


def get_available_tools(module: str) -> List[Dict[str, str]]:
    """Get list of available tools for a module.

    'implemented' tools have a real, working module under modules/<DOMAIN>/<tool>/
    that this CLI can deploy/scan/report against directly. 'catalog-only' entries
    are listed for domain coverage but require the vendor's own commercial
    account/API token — no amount of local engineering substitutes for that, so
    they are not implemented here.
    """
    tools_info = {
        'soc': [
            {'name': 'splunk', 'type': 'Enterprise', 'status': IMPLEMENTED, 'description': 'SIEM platform for security monitoring'},
            {'name': 'wazuh', 'type': 'Open Source', 'status': IMPLEMENTED, 'description': 'Open source security monitoring'},
            {'name': 'sentinel', 'type': 'Cloud', 'status': CATALOG_ONLY, 'description': 'Microsoft cloud-native SIEM'},
            {'name': 'qradar', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'IBM security analytics platform'},
            {'name': 'elastic', 'type': 'Open Source', 'status': CATALOG_ONLY, 'description': 'Elasticsearch-based SIEM'},
        ],
        'edr': [
            {'name': 'wazuh', 'type': 'Open Source', 'status': IMPLEMENTED, 'description': 'Open source EDR solution (shares the SOC/wazuh backend)'},
            {'name': 'crowdstrike', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Cloud-native endpoint protection'},
            {'name': 'sentinelone', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'AI-powered endpoint security'},
            {'name': 'defender', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Microsoft endpoint protection'},
        ],
        'netsec': [
            {'name': 'nmap', 'type': 'Open Source', 'status': IMPLEMENTED, 'description': 'Network discovery and port scanning'},
            {'name': 'paloalto', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Next-gen firewall platform'},
            {'name': 'fortinet', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'FortiGate security appliance'},
            {'name': 'cisco', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Cisco security solutions'},
            {'name': 'opnsense', 'type': 'Open Source', 'status': CATALOG_ONLY, 'description': 'Open source firewall'},
        ],
        'appsec': [
            {'name': 'zap', 'type': 'Open Source', 'status': IMPLEMENTED, 'description': 'OWASP ZAP web application scanning'},
            {'name': 'burpsuite', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Web application security testing'},
            {'name': 'nuclei', 'type': 'Open Source', 'status': CATALOG_ONLY, 'description': 'Vulnerability scanner'},
            {'name': 'postman', 'type': 'Tool', 'status': CATALOG_ONLY, 'description': 'API security testing'},
        ],
        'cloudsec': [
            {'name': 'iacauditor', 'type': 'Open Source', 'status': IMPLEMENTED, 'description': 'Static Terraform/Docker Compose misconfiguration scanner'},
            {'name': 'guardduty', 'type': 'Cloud', 'status': CATALOG_ONLY, 'description': 'AWS threat detection'},
            {'name': 'securityhub', 'type': 'Cloud', 'status': CATALOG_ONLY, 'description': 'AWS security posture management'},
            {'name': 'prismacloud', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Palo Alto cloud security'},
            {'name': 'mandiant', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Google Cloud security'},
        ],
        'vm': [
            {'name': 'trivy', 'type': 'Open Source', 'status': IMPLEMENTED, 'description': 'Filesystem and container image CVE scanning'},
            {'name': 'tenable', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Nessus vulnerability scanner'},
            {'name': 'qualys', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Cloud-based VM platform'},
            {'name': 'rapid7', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Nexpose vulnerability management'},
            {'name': 'openvas', 'type': 'Open Source', 'status': CATALOG_ONLY, 'description': 'Open source scanner'},
        ],
        'aisec': [
            {'name': 'llmriskscanner', 'type': 'Open Source', 'status': IMPLEMENTED, 'description': 'Heuristic OWASP LLM Top 10 pattern scanner for transcripts/logs'},
            {'name': 'darktrace', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'AI-powered threat detection'},
            {'name': 'vectra', 'type': 'Enterprise', 'status': CATALOG_ONLY, 'description': 'Network detection and response'},
        ]
    }

    return tools_info.get(module.lower(), [])
