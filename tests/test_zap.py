"""
Tests for the OWASP ZAP scan module (modules/APPSEC/zap). ZAP's REST API is
mocked via `requests` so these run without a live daemon; input validation,
authorization, and the unreachable-daemon error path are covered directly.
"""
from unittest.mock import patch

import requests

import modules.APPSEC.zap.scan as zap_scan


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def make_fake_get(alerts=None):
    alerts = alerts if alerts is not None else []

    def fake_get(url, params=None, timeout=None):
        if '/core/view/version/' in url:
            return FakeResponse({'version': '2.14.0'})
        if '/spider/action/scan/' in url:
            return FakeResponse({'scan': '0'})
        if '/spider/view/status/' in url:
            return FakeResponse({'status': '100'})
        if '/ascan/action/scan/' in url:
            return FakeResponse({'scan': '0'})
        if '/ascan/view/status/' in url:
            return FakeResponse({'status': '100'})
        if '/core/view/alerts/' in url:
            return FakeResponse({'alerts': alerts})
        raise AssertionError(f"Unexpected ZAP API call: {url}")

    return fake_get


class TestExecuteValidation:
    def test_missing_target_fails(self):
        assert zap_scan.execute() is False

    def test_public_target_without_override_fails(self):
        assert zap_scan.execute(target="http://8.8.8.8") is False


class TestDaemonUnreachable:
    def test_connection_error_reports_clear_message(self):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            assert zap_scan.execute(target="http://127.0.0.1:8080") is False


class TestSuccessfulScan:
    def test_quick_scan_skips_active_scan_and_saves_result(self, tmp_path, monkeypatch):
        import toolkit.state as state
        monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

        alerts = [
            {'alert': 'SQL Injection', 'risk': 'High', 'description': 'desc', 'solution': 'Use parameterized queries'},
        ]
        with patch("requests.get", side_effect=make_fake_get(alerts)):
            assert zap_scan.execute(target="http://127.0.0.1:8080", scan_type="quick") is True

        result = state.load_latest_result("appsec", "zap", operations=("scan",))
        assert result is not None
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "high"

    def test_full_scan_runs_active_scan(self, tmp_path, monkeypatch):
        import toolkit.state as state
        monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

        fake_get = make_fake_get(alerts=[])
        with patch("requests.get", side_effect=fake_get) as mock_get:
            assert zap_scan.execute(target="http://127.0.0.1:8080", scan_type="full") is True
            called_paths = [call.args[0] for call in mock_get.call_args_list]
            assert any('/ascan/action/scan/' in p for p in called_paths)

    def test_no_alerts_produces_zero_findings(self, tmp_path, monkeypatch):
        import toolkit.state as state
        monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

        with patch("requests.get", side_effect=make_fake_get(alerts=[])):
            assert zap_scan.execute(target="http://127.0.0.1:8080", scan_type="quick") is True

        result = state.load_latest_result("appsec", "zap", operations=("scan",))
        assert result["findings"] == []
