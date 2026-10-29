"""
ToolKit Utilities
Helper functions and utilities for the ToolKit framework
"""
import os
import sys
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import shutil
from rich.console import Console
from rich.logging import RichHandler

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("toolkit")


def get_version() -> str:
    """Get ToolKit version"""
    from toolkit import __version__
    return __version__


def check_dependencies() -> Dict[str, Dict[str, Any]]:
    """Check if required system dependencies are installed"""
    dependencies = {
        'docker': {
            'command': ['docker', '--version'],
            'installed': False,
            'version': None
        },
        'terraform': {
            'command': ['terraform', '--version'],
            'installed': False,
            'version': None
        },
        'kubectl': {
            'command': ['kubectl', 'version', '--client', '--short'],
            'installed': False,
            'version': None
        },
        'ansible': {
            'command': ['ansible', '--version'],
            'installed': False,
            'version': None
        },
        'aws-cli': {
            'command': ['aws', '--version'],
            'installed': False,
            'version': None
        },
        'python': {
            'command': [sys.executable, '--version'],
            'installed': True,
            'version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        }
    }
    
    for dep, info in dependencies.items():
        if dep == 'python':
            continue
            
        try:
            result = subprocess.run(
                info['command'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                info['installed'] = True
                info['version'] = result.stdout.strip().split('\n')[0]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            info['installed'] = False
    
    return dependencies


def run_command(command: list, cwd: Optional[Path] = None, env: Optional[Dict] = None) -> tuple:
    """
    Run a shell command and return output
    
    Args:
        command: Command as list of strings
        cwd: Working directory
        env: Environment variables
        
    Returns:
        Tuple of (success: bool, output: str)
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=cwd,
            env=env or os.environ.copy(),
            timeout=300
        )
        
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr
            
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def get_cloud_credentials(provider: str = 'aws') -> Dict[str, str]:
    """Get cloud provider credentials from environment"""
    if provider.lower() == 'aws':
        return {
            'AWS_ACCESS_KEY_ID': os.getenv('AWS_ACCESS_KEY_ID', ''),
            'AWS_SECRET_ACCESS_KEY': os.getenv('AWS_SECRET_ACCESS_KEY', ''),
            'AWS_REGION': os.getenv('AWS_REGION', 'us-east-1')
        }
    elif provider.lower() == 'azure':
        return {
            'AZURE_SUBSCRIPTION_ID': os.getenv('AZURE_SUBSCRIPTION_ID', ''),
            'AZURE_TENANT_ID': os.getenv('AZURE_TENANT_ID', ''),
            'AZURE_CLIENT_ID': os.getenv('AZURE_CLIENT_ID', ''),
            'AZURE_CLIENT_SECRET': os.getenv('AZURE_CLIENT_SECRET', '')
        }
    elif provider.lower() == 'gcp':
        return {
            'GOOGLE_APPLICATION_CREDENTIALS': os.getenv('GOOGLE_APPLICATION_CREDENTIALS', ''),
            'GCP_PROJECT_ID': os.getenv('GCP_PROJECT_ID', '')
        }
    return {}


def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    return False


def validate_url(url: str) -> bool:
    """Validate URL format"""
    import re
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))


def ensure_directory(path: Path) -> None:
    """Ensure directory exists, create if it doesn't"""
    path.mkdir(parents=True, exist_ok=True)


def load_env_file(env_file: Path) -> Dict[str, str]:
    """Load environment variables from .env file"""
    from dotenv import dotenv_values
    if env_file.exists():
        return dotenv_values(env_file)
    return {}


def get_timestamp() -> str:
    """Get current timestamp in ISO format"""
    from datetime import datetime
    return datetime.now().isoformat()


def generate_report_filename(tool: str, report_type: str = 'deployment') -> str:
    """Generate a standardized report filename"""
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{tool}_{report_type}_report_{timestamp}"


def check_port_available(port: int, host: str = 'localhost') -> bool:
    """Check if a port is available"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    sock.close()
    return result != 0


def get_local_ip() -> str:
    """Get local IP address"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def format_size(bytes_size: int) -> str:
    """Format bytes into human readable size"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


class ToolKitError(Exception):
    """Base exception for ToolKit errors"""
    pass


class ConfigurationError(ToolKitError):
    """Configuration related errors"""
    pass


class DeploymentError(ToolKitError):
    """Deployment related errors"""
    pass


class ScanError(ToolKitError):
    """Scan related errors"""
    pass
