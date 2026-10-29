"""
Tests for the Wazuh deployment module (modules/SOC/wazuh). The real stack is
multi-GB and slow to bring up, so these cover config validation, the dry-run
path, and container-health inspection with the Docker SDK mocked — not a live
deploy.
"""
from unittest.mock import MagicMock, patch

import docker

import modules.SOC.wazuh.config as wazuh_config
import modules.SOC.wazuh.deploy as wazuh_deploy


class TestValidate:
    def test_missing_env_file_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(wazuh_config, "ENV_FILE", tmp_path / "does-not-exist.env")
        assert wazuh_config.validate() is False

    def test_present_compose_and_env_passes(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("WAZUH_PASSWORD=example\n")
        monkeypatch.setattr(wazuh_config, "ENV_FILE", env_file)
        assert wazuh_config.validate() is True


class TestExecuteDryRun:
    def test_dry_run_skips_docker_and_reports_success(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("WAZUH_PASSWORD=example\n")
        monkeypatch.setattr(wazuh_config, "ENV_FILE", env_file)

        with patch("modules.SOC.wazuh.deploy.run_command") as mock_run:
            assert wazuh_deploy.execute(dry_run=True) is True
            mock_run.assert_not_called()

    def test_invalid_config_fails_before_docker(self, tmp_path, monkeypatch):
        monkeypatch.setattr(wazuh_config, "ENV_FILE", tmp_path / "missing.env")
        assert wazuh_deploy.execute(dry_run=True) is False


class TestCheckContainerHealth:
    def test_docker_unavailable_reports_unknown(self):
        with patch("docker.from_env", side_effect=docker.errors.DockerException("no daemon")):
            health = wazuh_deploy.check_container_health()
        assert all(h['status'] == 'unknown' for h in health)
        assert len(health) == len(wazuh_config.SERVICES)

    def test_missing_container_reports_not_found(self):
        fake_client = MagicMock()
        fake_client.containers.get.side_effect = docker.errors.NotFound("no such container")
        with patch("docker.from_env", return_value=fake_client):
            health = wazuh_deploy.check_container_health()
        assert all(h['status'] == 'not_found' for h in health)

    def test_running_container_reports_status(self):
        fake_container = MagicMock()
        fake_container.status = "running"
        fake_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z"}}
        fake_client = MagicMock()
        fake_client.containers.get.return_value = fake_container
        with patch("docker.from_env", return_value=fake_client):
            health = wazuh_deploy.check_container_health()
        assert all(h['status'] == 'running' for h in health)
