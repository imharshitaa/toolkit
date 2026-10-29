"""
IaC Auditor Configuration
Static, rule-based configuration for scanning Terraform and Docker Compose
files for common misconfigurations. No external binary or network access
required — every rule runs as plain Python text/YAML parsing.
"""

PUBLIC_CIDR = '0.0.0.0/0'

# Ports where exposing them to the public internet is rarely intentional.
SENSITIVE_PORTS = {
    22: 'SSH', 3389: 'RDP', 6379: 'Redis', 27017: 'MongoDB',
    5432: 'PostgreSQL', 3306: 'MySQL', 9200: 'Elasticsearch',
    8088: 'Splunk HEC', 8089: 'Splunk Management', 9997: 'Splunk Receiver',
}

# Keys that commonly hold credentials when assigned a literal (non-variable,
# non-empty) string value in Terraform. Matches as a substring (e.g.
# "splunk_password") rather than a whole word, since variable names are
# frequently prefixed/suffixed with a service or component name.
SECRET_KEY_PATTERN = r'(password|secret|api[_-]?key|access[_-]?key|token)'

TERRAFORM_GLOB = '*.tf'
COMPOSE_FILENAMES = {'docker-compose.yml', 'docker-compose.yaml'}


def validate() -> bool:
    """No external dependency — the auditor is pure Python and always usable."""
    return True


def get_config() -> dict:
    return {
        'public_cidr': PUBLIC_CIDR,
        'sensitive_ports': SENSITIVE_PORTS,
    }
