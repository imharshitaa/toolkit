"""
ToolKit Report Command
Generate professional consulting-style security reports
"""
import click
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from jinja2 import Template
from toolkit.core import ToolKitCore
from toolkit.utils import generate_report_filename, ensure_directory, logger

console = Console()
core = ToolKitCore()

@click.command()
@click.argument('module', type=click.Choice([
    'soc', 'edr', 'netsec', 'appsec', 'cloudsec', 'vm', 'aisec'
]))
@click.argument('tool')
@click.option('--format', '-f',
              type=click.Choice(['pdf', 'html', 'markdown', 'docx']),
              default='pdf',
              help='Report output format')
@click.option('--output-dir', '-o',
              type=click.Path(),
              default='./reports',
              help='Output directory for reports')
@click.option('--template',
              type=click.Choice(['executive', 'technical', 'compliance', 'custom']),
              default='technical',
              help='Report template type')
@click.option('--include-screenshots', is_flag=True,
              help='Include screenshots in report')
@click.option('--include-recommendations', is_flag=True,
              default=True,
              help='Include security recommendations')
@click.option('--compliance-framework',
              type=click.Choice(['nist', 'iso27001', 'pci-dss', 'hipaa', 'gdpr']),
              help='Map findings to compliance framework')
@click.option('--severity-filter',
              type=click.Choice(['critical', 'high', 'medium', 'low', 'all']),
              default='all',
              help='Filter findings by severity')
def report_command(module, tool, format, output_dir, template, 
                   include_screenshots, include_recommendations,
                   compliance_framework, severity_filter):
    """
    Generate professional security reports
    
    Examples:
        toolkit report soc splunk
        toolkit report appsec zap --format pdf --template executive
        toolkit report vm tenable --compliance-framework nist
        toolkit report cloudsec guardduty --severity-filter critical
    """
    
    # Create output directory
    output_path = Path(output_dir)
    ensure_directory(output_path)
    
    # Generate report filename
    filename = generate_report_filename(tool, 'security')
    full_path = output_path / f"{filename}.{format}"
    
    # Display report configuration
    console.print(Panel.fit(
        f"[bold cyan]Generating Report for {tool.upper()}[/bold cyan]\n"
        f"Module: {module.upper()}\n"
        f"Format: {format.upper()}\n"
        f"Template: {template}\n"
        f"Output: {full_path}",
        title="Report Configuration",
        border_style="cyan"
    ))
    
    # Prepare report parameters
    kwargs = {
        'format': format,
        'output_path': str(full_path),
        'template': template,
        'include_screenshots': include_screenshots,
        'include_recommendations': include_recommendations,
        'compliance_framework': compliance_framework,
        'severity_filter': severity_filter,
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'tool': tool,
            'module': module
        }
    }
    
    # Execute report generation
    console.print("\n[bold cyan]Generating report...[/bold cyan]")
    
    success = core.execute_operation(module, tool, 'report', **kwargs)
    
    if success:
        console.print(f"\n[bold green]✓ Report generated successfully![/bold green]")
        console.print(f"Report saved to: [cyan]{full_path}[/cyan]")
        
        # Display report stats
        if full_path.exists():
            size = full_path.stat().st_size
            console.print(f"File size: {size / 1024:.2f} KB")
    else:
        console.print(f"\n[bold red]✗ Report generation failed[/bold red]")
        console.print("[yellow]Check logs for more details[/yellow]")


def generate_html_report(data: dict, output_path: Path) -> bool:
    """Generate HTML report"""
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ tool_name }} Security Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #2c3e50; }
            .header { background: #3498db; color: white; padding: 20px; }
            .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; }
            .finding { margin: 10px 0; padding: 10px; }
            .critical { background: #e74c3c; color: white; }
            .high { background: #e67e22; color: white; }
            .medium { background: #f39c12; }
            .low { background: #27ae60; color: white; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{{ tool_name }} Security Report</h1>
            <p>Generated: {{ timestamp }}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{{ summary }}</p>
        </div>
        
        <div class="section">
            <h2>Findings</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.severity }}">
                <h3>{{ finding.title }}</h3>
                <p>{{ finding.description }}</p>
                <p><strong>Severity:</strong> {{ finding.severity }}</p>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
            {% for rec in recommendations %}
                <li>{{ rec }}</li>
            {% endfor %}
            </ul>
        </div>
    </body>
    </html>
    """
    
    try:
        template = Template(template_str)
        html_content = template.render(**data)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return True
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        return False
