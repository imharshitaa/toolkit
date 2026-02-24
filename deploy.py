"""
ToolKit Deploy Command
Handles deployment of security tools to cloud and local environments
"""
import click
from rich.console import Console
from rich.panel import Panel
from toolkit.core import ToolKitCore
from toolkit.utils import logger, check_dependencies

console = Console()
core = ToolKitCore()

@click.command()
@click.argument('module', type=click.Choice([
    'soc', 'edr', 'netsec', 'appsec', 'cloudsec', 'vm', 'aisec'
]))
@click.argument('tool')
@click.option('--environment', '-e', 
              type=click.Choice(['local', 'aws', 'azure', 'gcp', 'docker', 'kubernetes']),
              default='local',
              help='Deployment environment')
@click.option('--config-file', '-c',
              type=click.Path(exists=True),
              help='Custom configuration file')
@click.option('--dry-run', is_flag=True,
              help='Simulate deployment without executing')
@click.option('--skip-validation', is_flag=True,
              help='Skip configuration validation')
@click.option('--auto-approve', is_flag=True,
              help='Auto-approve deployment without prompting')
@click.option('--region', '-r',
              default='us-east-1',
              help='Cloud region (for cloud deployments)')
@click.option('--instance-type', '-i',
              help='Instance type (for cloud deployments)')
def deploy_command(module, tool, environment, config_file, dry_run, 
                  skip_validation, auto_approve, region, instance_type):
    """
    Deploy a security tool to specified environment
    
    Examples:
        toolkit deploy soc splunk
        toolkit deploy cloudsec guardduty --environment aws --region us-west-2
        toolkit deploy edr crowdstrike --config-file ./custom-config.yaml
    """
    
    # Display deployment info
    console.print(Panel.fit(
        f"[bold cyan]Deploying {tool.upper()}[/bold cyan]\n"
        f"Module: {module.upper()}\n"
        f"Environment: {environment}\n"
        f"Region: {region}",
        title="Deployment Configuration",
        border_style="cyan"
    ))
    
    # Validate configuration unless skipped
    if not skip_validation:
        console.print("\n[yellow]Validating configuration...[/yellow]")
        if not core.validate_tool_config(module, tool):
            console.print("[red]Configuration validation failed. Use --skip-validation to override.[/red]")
            return
        console.print("[green]✓ Configuration valid[/green]")
    
    # Check dependencies for cloud deployments
    if environment in ['aws', 'azure', 'gcp', 'kubernetes']:
        console.print("\n[yellow]Checking dependencies...[/yellow]")
        deps = check_dependencies()
        
        required_deps = {
            'aws': ['aws-cli', 'terraform'],
            'azure': ['terraform'],
            'gcp': ['terraform'],
            'kubernetes': ['kubectl', 'terraform']
        }
        
        for dep in required_deps.get(environment, []):
            if not deps.get(dep, {}).get('installed'):
                console.print(f"[red]✗ Missing dependency: {dep}[/red]")
                console.print(f"[yellow]Please install {dep} to continue[/yellow]")
                return
        console.print("[green]✓ All dependencies satisfied[/green]")
    
    # Confirm deployment
    if not auto_approve and not dry_run:
        if not click.confirm('\nProceed with deployment?'):
            console.print("[yellow]Deployment cancelled[/yellow]")
            return
    
    # Execute deployment
    if dry_run:
        console.print("\n[yellow]DRY RUN MODE - No changes will be made[/yellow]")
    
    console.print(f"\n[bold cyan]Deploying {tool}...[/bold cyan]")
    
    kwargs = {
        'environment': environment,
        'config_file': config_file,
        'dry_run': dry_run,
        'region': region,
        'instance_type': instance_type
    }
    
    success = core.execute_operation(module, tool, 'deploy', **kwargs)
    
    if success:
        console.print(f"\n[bold green]✓ {tool} deployed successfully![/bold green]")
        console.print(f"\nTo access the dashboard, run: [cyan]toolkit open {module} {tool}[/cyan]")
    else:
        console.print(f"\n[bold red]✗ Deployment failed[/bold red]")
        console.print("[yellow]Check logs for more details[/yellow]")
