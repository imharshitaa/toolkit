"""
Splunk Deployment Module
Handles Splunk deployment to various environments
"""
import time
from pathlib import Path
from typing import Dict, Any
import docker
import boto3
import botocore.exceptions
from toolkit.utils import logger, run_command, ensure_directory
from toolkit.state import save_result
from modules.SOC.splunk.config import get_config, validate, SPLUNK_CONFIG

def execute(**kwargs) -> bool:
    """
    Execute Splunk deployment

    Args:
        environment: Target environment (docker, aws, kubernetes, local)
        dry_run: Simulate without executing
        region: AWS region for cloud deployment
        instance_type: EC2 instance type

    Returns:
        bool: Success status

    Note:
        'aws' and 'kubernetes' environments use the caller's own AWS/kubeconfig
        credential chain (same as the AWS CLI or kubectl) — ToolKit never stores
        or embeds cloud credentials.
    """
    environment = kwargs.get('environment', 'docker')
    dry_run = kwargs.get('dry_run', False)

    logger.info(f"Deploying Splunk to {environment}")

    if dry_run:
        logger.info("DRY RUN MODE - Simulating deployment")
        return simulate_deployment(environment, kwargs)

    if not validate(require_non_default_password=True):
        return False

    deployment_methods = {
        'docker': deploy_docker,
        'local': deploy_local,
        'aws': deploy_aws,
        'kubernetes': deploy_kubernetes,
    }

    deploy_func = deployment_methods.get(environment)
    if not deploy_func:
        logger.error(f"Unsupported environment: {environment}")
        return False

    success = deploy_func(kwargs)
    save_result('soc', 'splunk', 'deploy', {
        'tool_name': 'Splunk Deployment',
        'summary': f"Deployment to '{environment}' {'succeeded' if success else 'failed'}.",
        'findings': [{
            'title': f"{environment} deployment",
            'description': 'Deployment completed successfully.' if success else 'Deployment failed — see logs.',
            'severity': 'info' if success else 'high',
        }],
        'recommendations': [] if success else ['Re-run with --dry-run to validate configuration before retrying.'],
        'environment': environment,
    })
    return success


def deploy_docker(config: Dict[str, Any]) -> bool:
    """Deploy Splunk using Docker"""
    logger.info("Starting Docker deployment")
    
    try:
        client = docker.from_env()
        
        # Get configuration
        splunk_config = get_config('docker')
        docker_config = splunk_config['deployment']
        
        # Create data directories
        data_dirs = ['./splunk-data/etc', './splunk-data/var']
        for dir_path in data_dirs:
            ensure_directory(Path(dir_path))
        
        # Check if container already exists
        try:
            existing = client.containers.get(docker_config['container_name'])
            logger.warning(f"Container {docker_config['container_name']} already exists")
            existing.remove(force=True)
            logger.info("Removed existing container")
        except docker.errors.NotFound:
            pass
        
        # Pull image
        logger.info(f"Pulling image: {docker_config['image']}")
        client.images.pull(docker_config['image'])
        
        # Create container
        logger.info("Creating Splunk container")
        container = client.containers.run(
            docker_config['image'],
            name=docker_config['container_name'],
            ports=docker_config['ports'],
            volumes=docker_config['volumes'],
            environment=docker_config['environment'],
            detach=True,
            restart_policy={'Name': 'unless-stopped'}
        )
        
        # Wait for Splunk to start
        logger.info("Waiting for Splunk to start...")
        time.sleep(30)
        
        # Verify container is running
        container.reload()
        if container.status == 'running':
            logger.info("✓ Splunk container is running")
            logger.info(f"Access Splunk at: http://localhost:{docker_config['ports']['8000']}")
            logger.info("Username: admin")
            logger.info("Password: value of the SPLUNK_PASSWORD environment variable used to deploy")
            return True
        else:
            logger.error(f"Container failed to start. Status: {container.status}")
            return False
            
    except Exception as e:
        logger.error(f"Docker deployment failed: {e}")
        return False


def deploy_local(config: Dict[str, Any]) -> bool:
    """Deploy Splunk locally"""
    logger.info("Starting local deployment")
    
    # Download and install Splunk
    splunk_installer = Path("./downloads/splunk-installer.tgz")
    install_dir = Path("/opt/splunk")
    
    if not splunk_installer.exists():
        logger.error("Splunk installer not found. Please download manually.")
        logger.info("Download from: https://www.splunk.com/en_us/download.html")
        return False
    
    # Extract installer
    logger.info("Extracting Splunk...")
    success, output = run_command([
        'tar', 'xzf', str(splunk_installer), '-C', '/opt/'
    ])
    
    if not success:
        logger.error(f"Extraction failed: {output}")
        return False
    
    # Start Splunk
    logger.info("Starting Splunk...")
    success, output = run_command([
        str(install_dir / 'bin' / 'splunk'),
        'start',
        '--accept-license',
        '--answer-yes',
        '--no-prompt',
        '--seed-passwd', SPLUNK_CONFIG['admin_password']
    ])
    
    if success:
        logger.info("✓ Splunk started successfully")
        return True
    else:
        logger.error(f"Failed to start Splunk: {output}")
        return False


def deploy_aws(config: Dict[str, Any]) -> bool:
    """
    Deploy Splunk to AWS EC2.

    Requires the caller's own AWS credentials (standard boto3 credential chain —
    env vars, ~/.aws/credentials, or an instance role). ToolKit never stores or
    embeds AWS credentials.

    Note: the admin password is passed via EC2 user-data, which AWS exposes
    through the instance metadata service to anything running on that instance.
    This is a known limitation of user-data bootstrapping, not unique to
    ToolKit — for production use, pull the password from AWS Secrets Manager
    inside the instance instead of embedding it at launch.
    """
    logger.info("Starting AWS deployment")

    region = config.get('region', 'us-east-1')
    instance_type = config.get('instance_type', 't3.xlarge')

    try:
        ec2 = boto3.client('ec2', region_name=region)

        user_data_script = f"""#!/bin/bash
wget -O splunk-9.1.0.tgz 'https://download.splunk.com/products/splunk/releases/9.1.0/linux/splunk-9.1.0-linux-x86_64.tgz'
tar xzf splunk-9.1.0.tgz -C /opt/
/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd {SPLUNK_CONFIG['admin_password']}
/opt/splunk/bin/splunk enable boot-start
"""

        logger.info(f"Launching EC2 instance in {region}")
        response = ec2.run_instances(
            ImageId='ami-0c55b159cbfafe1f0',  # Amazon Linux 2
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            UserData=user_data_script,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': 'Splunk-Enterprise'},
                        {'Key': 'Tool', 'Value': 'ToolKit'},
                    ]
                }
            ]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        logger.info(f"Instance created: {instance_id}")
        
        # Wait for instance to be running
        logger.info("Waiting for instance to start...")
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        # Get instance details
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        public_ip = instance_info['Reservations'][0]['Instances'][0].get('PublicIpAddress')
        
        logger.info(f"✓ Splunk deployed successfully")
        logger.info(f"Instance ID: {instance_id}")
        logger.info(f"Public IP: {public_ip}")
        logger.info(f"Access Splunk at: http://{public_ip}:8000")
        
        return True

    except botocore.exceptions.NoCredentialsError:
        logger.error(
            "No AWS credentials found. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY "
            "or configure ~/.aws/credentials — ToolKit uses your own AWS credential "
            "chain and never stores credentials itself."
        )
        return False
    except Exception as e:
        logger.error(f"AWS deployment failed: {e}")
        return False


def deploy_kubernetes(config: Dict[str, Any]) -> bool:
    """
    Deploy Splunk to Kubernetes.

    Requires the caller's own kubeconfig context (standard kubectl credential
    chain) — ToolKit never stores or embeds cluster credentials.
    """
    logger.info("Starting Kubernetes deployment")

    manifest = f"""
apiVersion: v1
kind: Namespace
metadata:
  name: security
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: splunk
  namespace: security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: splunk
  template:
    metadata:
      labels:
        app: splunk
    spec:
      containers:
      - name: splunk
        image: splunk/splunk:latest
        ports:
        - containerPort: 8000
        - containerPort: 8089
        env:
        - name: SPLUNK_START_ARGS
          value: "--accept-license"
        - name: SPLUNK_PASSWORD
          value: "{SPLUNK_CONFIG['admin_password']}"
---
apiVersion: v1
kind: Service
metadata:
  name: splunk-service
  namespace: security
spec:
  type: LoadBalancer
  ports:
  - port: 8000
    targetPort: 8000
  selector:
    app: splunk
"""
    
    # Save manifest
    manifest_file = Path('./splunk-k8s.yaml')
    with open(manifest_file, 'w') as f:
        f.write(manifest)
    
    # Apply manifest
    logger.info("Applying Kubernetes manifest")
    success, output = run_command(['kubectl', 'apply', '-f', str(manifest_file)])
    
    if success:
        logger.info("✓ Splunk deployed to Kubernetes")
        logger.info("Run 'kubectl get svc -n security' to get the service URL")
        return True
    else:
        logger.error(f"Kubernetes deployment failed: {output}")
        return False


def simulate_deployment(environment: str, config: Dict[str, Any]) -> bool:
    """Simulate deployment for dry-run mode"""
    logger.info(f"Simulating {environment} deployment:")
    logger.info("  - Would create Splunk instance")
    logger.info("  - Would configure indexes")
    logger.info("  - Would install apps")
    logger.info("  - Would configure data inputs")
    logger.info("✓ Simulation complete")
    return True
