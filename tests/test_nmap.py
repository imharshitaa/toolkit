"""
Tests for the nmap module (modules/NETSEC/nmap). The nmap binary is not
installed in CI/dev environments by default, so subprocess execution is
mocked; input validation and error-handling paths are covered directly.
"""
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import modules.NETSEC.nmap.scan as nmap_scan

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestExecuteValidation:
    def test_missing_target_fails(self):
        assert nmap_scan.execute() is False

    def test_missing_binary_fails_gracefully(self):
        with patch("shutil.which", return_value=None):
            assert nmap_scan.execute(target="192.168.1.1") is False

    def test_public_target_without_override_fails(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            assert nmap_scan.execute(target="8.8.8.8") is False


class TestExecuteSubprocessHandling:
    def test_timeout_is_handled(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=5)):
            assert nmap_scan.execute(target="192.168.1.1", timeout=5) is False

    def test_nonzero_exit_code_is_handled(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "some error"
            assert nmap_scan.execute(target="192.168.1.1") is False

    def test_successful_scan_parses_findings_and_saves(self, tmp_path, monkeypatch):
        import toolkit.state as state
        monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

        def fake_run(command, **kwargs):
            xml_path = Path(command[command.index("-oX") + 1])
            xml_path.write_text(SAMPLE_XML)
            result = type("Result", (), {})()
            result.returncode = 0
            result.stderr = ""
            return result

        with patch("shutil.which", return_value="/usr/bin/nmap"), \
             patch("subprocess.run", side_effect=fake_run):
            assert nmap_scan.execute(target="192.168.1.10") is True

        result = state.load_latest_result("netsec", "nmap", operations=("scan",))
        assert result is not None
        assert len(result["findings"]) == 1  # only the open port
        assert "22" in result["findings"][0]["title"]


class TestParseNmapXml:
    def test_parses_open_ports_only(self, tmp_path):
        xml_path = tmp_path / "scan.xml"
        xml_path.write_text(SAMPLE_XML)
        findings, host_count = nmap_scan._parse_nmap_xml(xml_path)
        assert host_count == 1
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
