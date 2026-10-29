"""
Tests for the Trivy module (modules/VM/trivy). The trivy binary is not
installed in CI/dev environments by default, so subprocess execution is
mocked; input validation and error-handling paths are covered directly.
"""
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import modules.VM.trivy.scan as trivy_scan

SAMPLE_REPORT = {
    "Results": [
        {
            "Target": "app/package-lock.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "minimist",
                    "InstalledVersion": "1.2.0",
                    "FixedVersion": "",
                    "Severity": "CRITICAL",
                },
            ],
        }
    ]
}


class TestExecuteValidation:
    def test_missing_target_fails(self):
        assert trivy_scan.execute() is False

    def test_missing_binary_fails_gracefully(self):
        with patch("shutil.which", return_value=None):
            assert trivy_scan.execute(target=".") is False


class TestExecuteSubprocessHandling:
    def test_timeout_is_handled(self, tmp_path):
        target_dir = tmp_path / "project"
        target_dir.mkdir()
        with patch("shutil.which", return_value="/usr/local/bin/trivy"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=5)):
            assert trivy_scan.execute(target=str(target_dir), timeout=5) is False

    def test_nonzero_exit_code_is_handled(self, tmp_path):
        target_dir = tmp_path / "project"
        target_dir.mkdir()
        with patch("shutil.which", return_value="/usr/local/bin/trivy"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "some error"
            assert trivy_scan.execute(target=str(target_dir)) is False

    def test_successful_fs_scan_parses_findings_and_saves(self, tmp_path, monkeypatch):
        import toolkit.state as state
        monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

        target_dir = tmp_path / "project"
        target_dir.mkdir()

        def fake_run(command, **kwargs):
            output_path = Path(command[command.index("--output") + 1])
            output_path.write_text(json.dumps(SAMPLE_REPORT))
            result = type("Result", (), {})()
            result.returncode = 0
            result.stderr = ""
            return result

        with patch("shutil.which", return_value="/usr/local/bin/trivy"), \
             patch("subprocess.run", side_effect=fake_run):
            assert trivy_scan.execute(target=str(target_dir)) is True

        result = state.load_latest_result("vm", "trivy", operations=("scan",))
        assert result is not None
        assert len(result["findings"]) == 2
        severities = {f["severity"] for f in result["findings"]}
        assert severities == {"high", "critical"}

    def test_image_target_is_authorization_checked(self):
        # Avoid a real DNS lookup: assert the guard is invoked and its
        # rejection is honored, rather than resolving a real public registry.
        with patch("shutil.which", return_value="/usr/local/bin/trivy"), \
             patch("modules.VM.trivy.scan.require_authorized_target",
                   side_effect=trivy_scan.UnauthorizedTargetError("blocked")) as mock_guard:
            assert trivy_scan.execute(target="docker.io/library/nginx:latest", target_type="image") is False
            mock_guard.assert_called_once()


class TestParseTrivyReport:
    def test_parses_all_vulnerabilities(self):
        findings, count = trivy_scan._parse_trivy_report(SAMPLE_REPORT)
        assert count == 2
        titles = [f["title"] for f in findings]
        assert any("CVE-2024-1234" in t for t in titles)
        assert any("CVE-2024-5678" in t for t in titles)

    def test_empty_report_has_no_findings(self):
        findings, count = trivy_scan._parse_trivy_report({"Results": []})
        assert findings == []
        assert count == 0
