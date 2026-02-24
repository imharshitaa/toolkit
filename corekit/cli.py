"""
ToolKit CLI - Main Entry Point
Command-line interface for cybersecurity product deployment and management
"""
import click
from rich.console import Console
from rich.table import Table
from toolkit.deploy import deploy_command
from toolkit.scan import scan_command
from toolkit.report import report_command
from toolkit.open_dashboard import open_command
from toolkit.utils import get_version, check_dependencies

console = Console()

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=get_version())
def main():
    """
    ToolKit - Cloud-based Cybersecurity Products Implementation Solutions
    
    Deploy, scan, and manage enterprise security tools from the command line.
    """
    pass

@main.command()
def version():
    """Display ToolKit version and status"""
    console.print(f"[bold cyan]ToolKit v{get_version()}[/bold cyan]")
    console.print("[green]Status: Operational[/green]")
    
@main.command()
def status():
    """Check system dependencies and configuration"""
    console.print("[bold cyan]Checking System Dependencies...[/bold cyan]\n")
    deps = check_dependencies()
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Dependency", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Version")
    
    for dep, info in deps.items():
        status_icon = "✓" if info['installed'] else "✗"
        status_color = "green" if info['installed'] else "red"
        table.add_row(
            dep,
            f"[{status_color}]{status_icon}[/{status_color}]",
            info.get('version', 'N/A')
        )
    
    console.print(table)

@main.command()
@click.argument('module', type=click.Choice([
    'soc', 'edr', 'netsec', 'appsec', 'cloudsec', 'vm', 'aisec'
]))
def list_tools(module):
    """List available tools for a specific module"""
    from toolkit.core import get_available_tools
    
    tools = get_available_tools(module)
    
    console.print(f"\n[bold cyan]Available tools for {module.upper()}:[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan", width=20)
    table.add_column("Type", style="yellow", width=15)
    table.add_column("Description", style="white")
    
    for tool in tools:
        table.add_row(tool['name'], tool['type'], tool['description'])
    
    console.print(table)

# Register commands
main.add_command(deploy_command, name='deploy')
main.add_command(scan_command, name='scan')
main.add_command(report_command, name='report')
main.add_command(open_command, name='open')

if __name__ == '__main__':
    main()
