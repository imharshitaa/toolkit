"""
ToolKit Scan Command
Execute security scans, simulations, and tests
"""
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from toolkit.core import ToolKitCore
from toolkit.utils import validate_ip, validate_url, logger

console = Console()
core = ToolKitCore()

@click.command()
@click.argument('module', type=click.Choice([
    'soc', 'edr', 'netsec', 'appsec', 'cloudsec', 'vm', 'aisec'
]))
@click.argument('tool')
@click.option('--target', '-t',
              required=True,
              help='Target IP, hostname, or URL')
@click.option('--scan-type', '-s',
              type=click.Choice(['quick', 'full', 'stealth', 'compliance', 'custom']),
              default='quick',
              help='Type of scan to perform')
@click.option('--ports', '-p',
              help='Port range (e.g., 1-1000, 80,443)')
@click.option('--output', '-o',
              type=click.Path(),
              help='Output file for scan results')
@click.option('--format', '-f',
              type=click.Choice(['json', 'xml', 'html', 'csv']),
              default='json',
              help='Output format')
@click.option('--verbose', '-v', is_flag=True,
              help='Verbose output')
@click.option('--threads', 
              type=int,
              default=10,
              help='Number of threads for scanning')
@click.option('--timeout',
              type=int,
              default=300,
              help='Scan timeout in seconds')
@click.option('--simulate', is_flag=True,
              help='Run attack simulation instead of scan')
def scan_command(module, tool, target, scan_type, ports, output, 
                format, verbose, threads, timeout, simulate):
    """
    Run security scans or attack simulations
    
    Examples:
        toolkit scan soc splunk --target 192.168.1.10
        toolkit scan appsec zap --target https://example.com --scan-type full
        toolkit scan vm tenable --target 10.0.0.0/24 --output results.json
        toolkit scan soc wazuh --target 192.168.1.5 --simulate
    """
    
    # Validate target
    is_valid = False
    target_type = None
    
    if validate_ip(target):
        is_valid = True
        target_type = "IP Address"
    elif validate_url(target):
        is_valid = True
        target_type = "URL"
    elif '/' in target:  # CIDR notation
        is_valid = True
        target_type = "Network Range"
    else:
        # Assume hostname
        is_valid = True
        target_type = "Hostname"
    
    if not is_valid:
        console.print("[red]Invalid target format[/red]")
        return
    
    # Display scan configuration
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
    
    scan_info.add_row("Threads:", str(threads))
    scan_info.add_row("Timeout:", f"{timeout}s")
    
    if simulate:
        scan_info.add_row("Mode:", "Attack Simulation")
    
    console.print(Panel(scan_info, title="Scan Configuration", border_style="cyan"))
    
    # Prepare scan parameters
    kwargs = {
        'target': target,
        'scan_type': scan_type,
        'ports': ports,
        'output': output,
        'format': format,
        'verbose': verbose,
        'threads': threads,
        'timeout': timeout,
        'simulate': simulate
    }
    
    # Execute scan
    operation = 'simulate' if simulate else 'scan'
    
    console.print(f"\n[bold cyan]Starting {operation}...[/bold cyan]")
    
    success = core.execute_operation(module, tool, operation, **kwargs)
    
    if success:
        console.print(f"\n[bold green]✓ {operation.capitalize()} completed successfully![/bold green]")
        
        if output:
            console.print(f"Results saved to: [cyan]{output}[/cyan]")
        
        # Generate report suggestion
        console.print(f"\nTo generate a detailed report, run:")
        console.print(f"[cyan]toolkit report {module} {tool}[/cyan]")
    else:
        console.print(f"\n[bold red]✗ {operation.capitalize()} failed[/bold red]")
        console.print("[yellow]Check logs for more details[/yellow]")
