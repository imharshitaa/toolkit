# ToolKit

**Cloud-based Cybersecurity Products Implementation Solutions**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive CLI framework for deploying, configuring, and managing enterprise cybersecurity tools across multiple domains including SOC/SIEM, EDR/XDR, Network Security, Application Security, Cloud Security, and more.

## Features

- **Multi-Domain Support**: SOC, EDR, Network, Application, Cloud, VM, AI Security
- **Cloud-Native**: Deploy to AWS, Azure, GCP, Kubernetes, or Docker
- **Attack Simulation**: Built-in MITRE ATT&CK scenarios for detection testing
- **Professional Reports**: Generate executive and technical security reports
- **Extensible Architecture**: Easy to add new tools and modules
- **Open Source First**: Prioritizes open-source alternatives alongside enterprise tools

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Supported Tools](#supported-tools)
- [Usage](#usage)
- [Architecture](#architecture)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Quick Start

```bash
# Clone repository
git clone https://github.com/imharshitaa/toolkit.git
cd toolkit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install ToolKit CLI
pip install -e .

# Verify installation
toolkit --version

# Deploy your first tool (Splunk via Docker)
toolkit deploy soc splunk --environment docker

# Access Splunk Web UI at http://localhost:8000
# Default credentials: admin / changeme
```

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- Docker (for containerized deployments)
- AWS CLI (for AWS deployments)
- kubectl (for Kubernetes deployments)
- Terraform (for infrastructure as code)

### Install from Source

```bash
git clone https://github.com/imharshitaa/toolkit.git
cd toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Install via pip (coming soon)

```bash
pip install toolkit-cybersec
```

## 🛠️ Supported Tools

### SOC / SIEM

| Tool | Type | Description |
|------|------|-------------|
| **Splunk** | Enterprise | Leading SIEM platform |
| **Microsoft Sentinel** | Cloud | Cloud-native SIEM |
| **IBM QRadar** | Enterprise | Security analytics platform |
| **Elastic** | Open Source | Elasticsearch-based SIEM |
| **Wazuh** | Open Source | Open source security monitoring |

### EDR / XDR

| Tool | Type | Description |
|------|------|-------------|
| **CrowdStrike Falcon** | Enterprise | Cloud-native endpoint protection |
| **SentinelOne** | Enterprise | AI-powered endpoint security |
| **Microsoft Defender** | Enterprise | Endpoint detection and response |
| **Wazuh** | Open Source | Open source EDR solution |

### Network Security

| Tool | Type | Description |
|------|------|-------------|
| **Palo Alto** | Enterprise | Next-generation firewall |
| **Fortinet** | Enterprise | FortiGate security appliance |
| **Cisco Secure** | Enterprise | Network security solutions |
| **OPNsense** | Open Source | Open source firewall |
| **pfSense** | Open Source | FreeBSD-based firewall |

### Application Security

| Tool | Type | Description |
|------|------|-------------|
| **Burp Suite** | Enterprise | Web application security testing |
| **OWASP ZAP** | Open Source | Penetration testing tool |
| **Nuclei** | Open Source | Vulnerability scanner |
| **Postman** | Tool | API security testing |

### Cloud Security

| Tool | Type | Description |
|------|------|-------------|
| **AWS GuardDuty** | Cloud | AWS threat detection |
| **Security Hub** | Cloud | AWS security posture management |
| **Prisma Cloud** | Enterprise | Palo Alto cloud security |
| **Mandiant** | Enterprise | Google Cloud security |

### Vulnerability Management

| Tool | Type | Description |
|------|------|-------------|
| **Tenable Nessus** | Enterprise | Vulnerability scanner |
| **Qualys** | Enterprise | Cloud-based VM platform |
| **Rapid7** | Enterprise | Nexpose vulnerability management |
| **OpenVAS** | Open Source | Open source scanner |

## 💻 Usage

### Basic Commands

```bash
# Check system status and dependencies
toolkit status

# List available tools for a module
toolkit list-tools soc
toolkit list-tools edr
toolkit list-tools appsec

# Get help for any command
toolkit --help
toolkit deploy --help
toolkit scan --help
```

### Deployment Examples

#### Deploy Splunk (Docker)
```bash
toolkit deploy soc splunk --environment docker
```

#### Deploy to AWS
```bash
toolkit deploy soc splunk \
  --environment aws \
  --region us-east-1 \
  --instance-type t3.xlarge
```

#### Deploy to Kubernetes
```bash
toolkit deploy edr wazuh --environment kubernetes
```

#### Deploy with Custom Configuration
```bash
toolkit deploy soc splunk \
  --config-file ./configs/splunk-prod.yaml \
  --environment aws \
  --auto-approve
```

### Scanning and Testing

#### Run Application Security Scan
```bash
toolkit scan appsec zap \
  --target https://example.com \
  --scan-type full \
  --output results.json
```

#### Run Vulnerability Scan
```bash
toolkit scan vm tenable \
  --target 192.168.1.0/24 \
  --scan-type compliance \
  --format html
```

#### Run Attack Simulation
```bash
# Simulate MITRE ATT&CK techniques
toolkit scan soc splunk \
  --target localhost:8088 \
  --simulate \
  --scenario brute_force
```

### Report Generation

```bash
# Generate PDF security report
toolkit report soc splunk \
  --format pdf \
  --template executive

# Generate technical report with screenshots
toolkit report appsec zap \
  --format html \
  --template technical \
  --include-screenshots

# Generate compliance report
toolkit report vm tenable \
  --format docx \
  --compliance-framework nist \
  --severity-filter critical
```

### Dashboard Access

```bash
# Open tool dashboard in browser
toolkit open soc splunk
toolkit open appsec zap
toolkit open cloudsec guardduty

# Print URL instead of opening browser
toolkit open soc splunk --print-url

# Connect to custom host
toolkit open soc splunk --host 192.168.1.10 --port 8000
```

## 🏗️ Architecture

```
toolkit/
│
├── toolkit/              # Core CLI engine
│   ├── cli.py           # Main CLI entry point
│   ├── core.py          # Execution engine
│   ├── deploy.py        # Deployment logic
│   ├── scan.py          # Scanning logic
│   ├── report.py        # Report generation
│   ├── open_dashboard.py # Dashboard opener
│   └── utils.py         # Helper functions
│
├── modules/             # Security domain modules
│   ├── SOC/            # SIEM tools
│   │   ├── splunk/
│   │   │   ├── config.py      # Configuration
│   │   │   ├── deploy.py      # Deployment logic
│   │   │   ├── simulate.py    # Attack simulation
│   │   │   ├── detections.md  # Detection rules
│   │   │   └── README.md      # Documentation
│   │   ├── qradar/
│   │   └── elastic/
│   │
│   ├── APPSEC/         # Application security
│   ├── CLOUDSEC/       # Cloud security
│   ├── NETSEC/         # Network security
│   ├── EDR/            # Endpoint detection
│   ├── VM/             # Vulnerability management
│   └── AISEC/          # AI-powered security
│
└── labs/               # Lab environments
    ├── docker/         # Docker Compose setups
    ├── terraform/      # IaC templates
    └── k8s/           # Kubernetes manifests
```

### Module Structure

Each security tool follows a consistent structure:

```
tool_name/
├── config.py         # Tool configuration
├── deploy.py         # Deployment implementation
├── simulate.py       # Attack/test simulation (optional)
├── detections.md     # Detection rules (SIEM/EDR)
└── README.md         # Tool-specific documentation
```

## 🔬 Labs and Testing

### Docker Lab Environment

```bash
cd labs/docker
docker-compose up -d

# Access services:
# Splunk: http://localhost:8000
# ZAP: http://localhost:8080
# Wazuh: http://localhost:5601
# Kibana: http://localhost:5602
```

### AWS Infrastructure

```bash
cd labs/terraform
terraform init
terraform plan
terraform apply

# Outputs will show:
# - Splunk public IP
# - GuardDuty detector ID
# - CloudTrail ARN
```

### Attack Simulation

The toolkit includes built-in attack simulations based on MITRE ATT&CK:

```bash
# Brute force attack (T1110)
toolkit scan soc splunk --simulate --scenario brute_force

# Lateral movement (T1021)
toolkit scan soc splunk --simulate --scenario lateral_movement

# Data exfiltration (T1048)
toolkit scan soc splunk --simulate --scenario data_exfiltration
```

## 🔧 Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/imharshitaa/toolkit.git
cd toolkit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=toolkit --cov-report=html

# Run specific test file
pytest tests/test_cli.py -v

# Run tests for a specific module
pytest tests/test_cli.py::TestCLI::test_version_command
```

### Code Quality

```bash
# Format code
black toolkit/ modules/ tests/

# Lint code
flake8 toolkit/ modules/ tests/

# Type checking
mypy toolkit/

# Security scan
bandit -r toolkit/
```

### Adding a New Tool

1. Create module directory:
```bash
mkdir -p modules/MODULE_NAME/tool_name
```

2. Create required files:
```bash
touch modules/MODULE_NAME/tool_name/config.py
touch modules/MODULE_NAME/tool_name/deploy.py
touch modules/MODULE_NAME/tool_name/README.md
```

3. Implement `config.py`:
```python
def get_config(environment: str = 'docker') -> dict:
    return {
        'tool_config': {...},
        'deployment': {...}
    }

def validate() -> bool:
    # Validation logic
    return True
```

4. Implement `deploy.py`:
```python
def execute(**kwargs) -> bool:
    # Deployment logic
    return True
```

5. Add tool to `core.py` in `get_available_tools()` function

6. Test your implementation:
```bash
toolkit deploy module_name tool_name --dry-run
```

## 📚 Documentation

- [Splunk Module Documentation](modules/SOC/splunk/README.md)
- [ZAP Module Documentation](modules/APPSEC/zap/README.md)
- [Detection Rules](modules/SOC/splunk/detections.md)
- [Architecture Overview](docs/architecture.md)
- [API Reference](docs/api.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Add new tool modules
- ✅ Write tests
- 🎨 Improve UI/UX

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- OWASP Foundation
- Splunk Community
- All open-source security tool maintainers

## 📞 Support

- 📧 Email: support@toolkit.security
- 💬 Discord: [Join our community](https://discord.gg/toolkit)
- 🐛 Issues: [GitHub Issues](https://github.com/imharshitaa/toolkit/issues)
- 📖 Docs: [Documentation](https://toolkit.readthedocs.io)

## 🗺️ Roadmap

- [ ] Add support for more SIEM platforms (Sumo Logic, LogRhythm)
- [ ] Implement SOAR integration (Tines, Shuffle, Phantom)
- [ ] Add compliance frameworks (SOC 2, PCI-DSS, HIPAA)
- [ ] Create web UI dashboard
- [ ] Add API for programmatic access
- [ ] Implement machine learning-based threat detection
- [ ] Support for hybrid cloud deployments
- [ ] Integration with threat intelligence feeds

---

**Made with ❤️ by the ToolKit Team**

⭐ Star us on GitHub if you find this project useful!
