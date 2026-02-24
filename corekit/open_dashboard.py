"""
ToolKit Dashboard Opener
Open security tool dashboards in browser
"""
import click
import webbrowser
from rich.console import Console
from rich.panel import Panel
from toolkit.core import ToolKitCore
from toolkit.utils import logger

console = Console()
core = ToolKitCore()

# Dashboard URLs for common tools
DASHBOARD_URLS = {
    'splunk': 'http://localhost:8000',
    'sentinel': 'https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights',
    'qradar': 'https://localhost/console',
    'elastic': 'http://localhost:5601',
    'wazuh': 'http://localhost:5601/app/wazuh',
    'crowdstrike': 'https://falcon.crowdstrike.com',
    'sentinelone': 'https://console.sentinelone.net',
    'defender': 'https://security.microsoft.com',
    'paloalto': 'https://localhost',
    'fortinet': 'https://localhost',
    'opnsense': 'https://localhost',
    'burpsuite': 'http://localhost:8080',
    'zap': 'http://localhost:8080',
    'guardduty': 'https://console.aws.amazon.com/guardduty',
    'securityhub': 'https://console.aws.amazon.com/securityhub',
    'prismacloud': 'https://app.prismacloud.io',
    'tenable': 'https://localhost:8834',
    'qualys': 'https://qualysguard.qualys.com',
    'openvas': 'https://localhost:9392',
    'darktrace': 'https://localhost',
    'vectra': 'https://localhost',
}

@click.command()
@click.argument('module', type=click.Choice([
    'soc', 'edr', 'netsec', 'appsec', 'cloudsec', 'vm', 'aisec'
]))
@click.argument('tool')
@click.option('--host',
              help='Custom host address')
@click.option('--port',
              type=int,
              help='Custom port number')
@click.option('--print-url', is_flag=True,
              help='Print URL instead of opening browser')
def open_command(module, tool, host, port, print_url):
    """
    Open security tool dashboard in browser
    
    Examples:
        toolkit open soc splunk
        toolkit open appsec zap --host 192.168.1.10
        toolkit open cloudsec guardduty --print-url
    """
    
    # Get base URL for tool
    base_url = DASHBOARD_URLS.get(tool.lower())
    
    if not base_url:
        console.print(f"[yellow]No default URL configured for {tool}[/yellow]")
        console.print("[yellow]Use --host and --port to specify custom URL[/yellow]")
        
        if host:
            protocol = 'https' if port == 443 else 'http'
            base_url = f"{protocol}://{host}"
            if port and port not in [80, 443]:
                base_url += f":{port}"
        else:
            return
    else:
        # Override with custom host/port if provided
        if host or port:
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            protocol = parsed.scheme
            
            custom_host = host if host else parsed.netloc.split(':')[0]
            custom_port = port if port else (parsed.port or (443 if protocol == 'https' else 80))
            
            base_url = f"{protocol}://{custom_host}"
            if custom_port not in [80, 443]:
                base_url += f":{custom_port}"
    
    # Display info
    console.print(Panel.fit(
        f"[bold cyan]Opening {tool.upper()} Dashboard[/bold cyan]\n"
        f"Module: {module.upper()}\n"
        f"URL: {base_url}",
        title="Dashboard Access",
        border_style="cyan"
    ))
    
    if print_url:
        console.print(f"\n[cyan]{base_url}[/cyan]")
    else:
        try:
            console.print("\n[yellow]Opening in browser...[/yellow]")
            webbrowser.open(base_url)
            console.print("[green]✓ Dashboard opened[/green]")
        except Exception as e:
            console.print(f"[red]Failed to open browser: {e}[/red]")
            console.print(f"\nManually navigate to: [cyan]{base_url}[/cyan]")
