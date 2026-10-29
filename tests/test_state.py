"""
Tests for toolkit.state — persistence of scan/simulate/deploy results used by
`toolkit report` to render real data instead of placeholder content.
"""
import json

import toolkit.state as state


def test_save_and_load_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

    state.save_result("netsec", "nmap", "scan", {"summary": "found 1 host", "findings": []})
    result = state.load_latest_result("netsec", "nmap", operations=("scan",))

    assert result is not None
    assert result["module"] == "netsec"
    assert result["tool"] == "nmap"
    assert result["operation"] == "scan"
    assert result["summary"] == "found 1 host"
    assert "generated_at" in result


def test_load_latest_returns_none_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")
    assert state.load_latest_result("netsec", "nmap") is None


def test_load_latest_picks_most_recent_operation(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")

    # Backdate the "deploy" result so ordering doesn't depend on clock
    # resolution between two back-to-back save_result() calls.
    deploy_path = state.save_result("soc", "splunk", "deploy", {"summary": "deployed"})
    payload = json.loads(deploy_path.read_text())
    payload["generated_at"] = "2020-01-01T00:00:00"
    deploy_path.write_text(json.dumps(payload))

    state.save_result("soc", "splunk", "scan", {"summary": "scanned"})

    result = state.load_latest_result("soc", "splunk", operations=("scan", "deploy"))
    assert result["summary"] == "scanned"
