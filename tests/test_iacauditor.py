"""
Tests for the IaC Auditor module (modules/CLOUDSEC/iacauditor) — a pure
Python static scanner, so it is fully testable with fixture files and no
mocking or external binaries.
"""
from modules.CLOUDSEC.iacauditor.scan import _scan_compose_file, _scan_terraform_file

BAD_TERRAFORM = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH"
  }
}

resource "aws_instance" "example" {
  user_data = templatefile("install.sh", {
    admin_password = "SuperSecret123!"
  })
}
"""

CLEAN_TERRAFORM = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
    description = "SSH"
  }
}

resource "aws_instance" "example" {
  user_data = templatefile("install.sh", {
    admin_password = var.admin_password
  })
}
"""

BAD_COMPOSE = """
services:
  app:
    image: example:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      DB_PASSWORD: hardcoded-secret-value
"""

CLEAN_COMPOSE = """
services:
  app:
    image: example:latest
    environment:
      DB_PASSWORD: ${DB_PASSWORD:?Set DB_PASSWORD in your .env file}
"""


class TestTerraformScanning:
    def test_flags_public_ssh_ingress(self, tmp_path):
        tf_file = tmp_path / "bad.tf"
        tf_file.write_text(BAD_TERRAFORM)
        findings = _scan_terraform_file(tf_file)
        titles = [f["title"] for f in findings]
        assert any("Public ingress" in t for t in titles)
        ssh_finding = next(f for f in findings if "Public ingress" in f["title"])
        assert ssh_finding["severity"] == "critical"

    def test_flags_hardcoded_secret(self, tmp_path):
        tf_file = tmp_path / "bad.tf"
        tf_file.write_text(BAD_TERRAFORM)
        findings = _scan_terraform_file(tf_file)
        assert any("Hardcoded secret" in f["title"] for f in findings)

    def test_clean_terraform_has_no_findings(self, tmp_path):
        tf_file = tmp_path / "clean.tf"
        tf_file.write_text(CLEAN_TERRAFORM)
        assert _scan_terraform_file(tf_file) == []


class TestComposeScanning:
    def test_flags_privileged_container(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(BAD_COMPOSE)
        findings = _scan_compose_file(compose_file)
        assert any("Privileged container" in f["title"] for f in findings)

    def test_flags_docker_socket_mount(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(BAD_COMPOSE)
        findings = _scan_compose_file(compose_file)
        assert any("Docker socket exposed" in f["title"] for f in findings)

    def test_flags_hardcoded_env_secret(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(BAD_COMPOSE)
        findings = _scan_compose_file(compose_file)
        assert any("Hardcoded secret" in f["title"] for f in findings)

    def test_clean_compose_has_no_findings(self, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(CLEAN_COMPOSE)
        assert _scan_compose_file(compose_file) == []


class TestExecute:
    def test_execute_scans_directory_and_saves_result(self, tmp_path, monkeypatch):
        import modules.CLOUDSEC.iacauditor.scan as scan_module
        import toolkit.state as state

        monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

        iac_dir = tmp_path / "iac"
        iac_dir.mkdir()
        (iac_dir / "main.tf").write_text(BAD_TERRAFORM)

        assert scan_module.execute(target=str(iac_dir)) is True

        result = state.load_latest_result("cloudsec", "iacauditor", operations=("scan",))
        assert result is not None
        assert len(result["findings"]) >= 2

    def test_execute_rejects_missing_target(self):
        import modules.CLOUDSEC.iacauditor.scan as scan_module
        assert scan_module.execute(target="/no/such/path/here") is False
