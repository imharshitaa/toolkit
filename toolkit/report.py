"""
ToolKit Report Command
Render the most recent scan/simulate/deploy result for a tool into a report
"""
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from toolkit.core import ToolKitCore
from toolkit.utils import generate_report_filename, ensure_directory

console = Console()
core = ToolKitCore()


@click.command()
@click.argument('module', type=click.Choice([
    'soc', 'edr', 'netsec', 'appsec', 'cloudsec', 'vm', 'aisec'
]))
@click.argument('tool')
@click.option('--format', '-f',
              type=click.Choice(['html', 'markdown']),
              default='html',
              help='Report output format')
@click.option('--output-dir', '-o',
              type=click.Path(),
              default='./reports',
              help='Output directory for reports')
@click.option('--severity-filter',
              type=click.Choice(['critical', 'high', 'medium', 'low', 'all']),
              default='all',
              help='Minimum severity to include in the report')
def report_command(module, tool, format, output_dir, severity_filter):
    """
    Generate a report from the most recent scan/simulate/deploy result

    A scan, simulation, or deployment must have been run first — reports are
    built from the real result of that run, not from placeholder data.

    Examples:
        toolkit report soc splunk
        toolkit report appsec zap --format markdown
        toolkit report cloudsec iacauditor --severity-filter high
    """
    output_path = Path(output_dir)
    ensure_directory(output_path)

    filename = generate_report_filename(tool, 'security')
    extension = 'md' if format == 'markdown' else 'html'
    full_path = output_path / f"{filename}.{extension}"

    console.print(Panel.fit(
        f"[bold cyan]Generating Report for {tool.upper()}[/bold cyan]\n"
        f"Module: {module.upper()}\n"
        f"Format: {format.upper()}\n"
        f"Output: {full_path}",
        title="Report Configuration",
        border_style="cyan"
    ))

    kwargs = {
        'format': format,
        'output_path': str(full_path),
        'severity_filter': severity_filter,
    }

    console.print("\n[bold cyan]Generating report...[/bold cyan]")

    success = core.execute_operation(module, tool, 'report', **kwargs)

    if success:
        console.print(f"\n[bold green]✓ Report generated successfully![/bold green]")
        console.print(f"Report saved to: [cyan]{full_path}[/cyan]")

        if full_path.exists():
            size = full_path.stat().st_size
            console.print(f"File size: {size / 1024:.2f} KB")
    else:
        console.print(f"\n[bold red]✗ Report generation failed[/bold red]")
        console.print("[yellow]Check logs for more details[/yellow]")
