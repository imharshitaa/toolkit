"""
ToolKit Scan Command
Execute security scans and attack simulations
"""
import ipaddress

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from toolkit.core import ToolKitCore
from toolkit.utils import validate_ip, validate_url, logger

console = Console()
core = ToolKitCore()


def classify_target(target: str) -> str:
    """Best-effort classification of a target for display purposes."""
    if validate_ip(target):
        return "IP Address"
    if validate_url(target):
        return "URL"
    try:
        ipaddress.ip_network(target, strict=False)
        return "Network Range (CIDR)"
    except ValueError:
        return "Hostname"


@click.command()
@click.argument('module', type=click.Choice([
    'soc', 'edr', 'netsec', 'appsec', 'cloudsec', 'vm', 'aisec'
]))
@click.argument('tool')
@click.option('--target', '-t',
              required=True,
              help='Target IP, hostname, URL, or CIDR range')
@click.option('--scan-type', '-s',
              type=click.Choice(['quick', 'full', 'stealth', 'compliance', 'custom']),
              default='quick',
              help='Type of scan to perform')
@click.option('--ports', '-p',
              help='Port range (e.g., 1-1000, 80,443)')
@click.option('--output', '-o',
              type=click.Path(),
              help='Output file for raw scan results')
@click.option('--verbose', '-v', is_flag=True,
              help='Verbose output')
@click.option('--timeout',
              type=int,
              default=300,
              help='Scan timeout in seconds')
@click.option('--simulate', is_flag=True,
              help='Run attack simulation instead of a scan')
@click.option('--scenario',
              help='Specific simulation scenario to run (simulate mode only; default: all)')
@click.option('--i-have-authorization', 'allow_unsafe', is_flag=True,
              help='Required to target hosts outside private/loopback ranges. '
                   'Only use against systems you own or are explicitly authorized to test.')
def scan_command(module, tool, target, scan_type, ports, output,
                  verbose, timeout, simulate, scenario, allow_unsafe):
    """
    Run security scans or attack simulations

    Examples:
        toolkit scan appsec zap --target http://localhost:8080
        toolkit scan netsec nmap --target 192.168.1.0/24 --scan-type quick
        toolkit scan soc splunk --target localhost:8088 --simulate
    """
    target_type = classify_target(target)

    scan_info = Table(show_header=False, box=None)
    scan_info.add_column(style="cyan", width=20)
    scan_info.add_column(style="white")

    scan_info.add_row("Module:", module.upper())
    scan_info.add_row("Tool:", tool)
    scan_info.add_row("Target:", target)
    scan_info.add_row("Target Type:", target_type)
    scan_info.add_row("Scan Type:", scan_type)

    if ports:
        scan_info.add_row("Ports:", ports)

    scan_info.add_row("Timeout:", f"{timeout}s")

    if simulate:
        scan_info.add_row("Mode:", "Attack Simulation")

    console.print(Panel(scan_info, title="Scan Configuration", border_style="cyan"))

    kwargs = {
        'target': target,
        'scan_type': scan_type,
        'ports': ports,
        'output': output,
        'verbose': verbose,
        'timeout': timeout,
        'simulate': simulate,
        'scenario': scenario,
        'allow_unsafe': allow_unsafe,
    }

    operation = 'simulate' if simulate else 'scan'

    console.print(f"\n[bold cyan]Starting {operation}...[/bold cyan]")

    success = core.execute_operation(module, tool, operation, **kwargs)

    if success:
        console.print(f"\n[bold green]✓ {operation.capitalize()} completed successfully![/bold green]")

        if output:
            console.print(f"Results saved to: [cyan]{output}[/cyan]")

        console.print(f"\nTo generate a detailed report, run:")
        console.print(f"[cyan]toolkit report {module} {tool}[/cyan]")
    else:
        console.print(f"\n[bold red]✗ {operation.capitalize()} failed[/bold red]")
        console.print("[yellow]Check logs for more details[/yellow]")
