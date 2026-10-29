"""
Tests for the Splunk attack simulation module (modules/SOC/splunk). Event
generation and the local-log fallback are pure Python / filesystem, so they
are tested directly; HEC delivery goes through a mocked `requests.post`.
"""
from unittest.mock import patch

import modules.SOC.splunk.simulate as splunk_simulate


class TestGenerateEvents:
    def test_generates_expected_event_count_per_scenario(self):
        for scenario, config in splunk_simulate.ATTACK_SCENARIOS.items():
            events = splunk_simulate.generate_events(scenario)
            assert len(events) == config['events']
            assert all(e['mitre_technique'] == config['technique_id'] for e in events)

    def test_unknown_scenario_raises(self):
        import pytest
        with pytest.raises(KeyError):
            splunk_simulate.generate_events("not_a_real_scenario")


class TestDeliverEvents:
    def test_no_hec_token_falls_back_to_local_log(self, tmp_path, monkeypatch):
        monkeypatch.setattr(splunk_simulate, "EVENT_LOG_DIR", tmp_path / "events")
        monkeypatch.setitem(splunk_simulate.DATA_INPUTS['http'], 'token', '')

        events = splunk_simulate.generate_events('persistence')
        destination, location = splunk_simulate.deliver_events(events, "localhost:8088", "persistence")

        assert destination == "local_log"
        assert (tmp_path / "events").exists()

    def test_unreachable_hec_falls_back_to_local_log(self, tmp_path, monkeypatch):
        monkeypatch.setattr(splunk_simulate, "EVENT_LOG_DIR", tmp_path / "events")
        monkeypatch.setitem(splunk_simulate.DATA_INPUTS['http'], 'token', 'fake-token')

        with patch("requests.post", side_effect=splunk_simulate.requests.exceptions.ConnectionError("refused")):
            events = splunk_simulate.generate_events('brute_force')
            destination, location = splunk_simulate.deliver_events(events, "localhost:8088", "brute_force")

        assert destination == "local_log"


class TestExecute:
    def test_public_target_without_override_fails(self):
        assert splunk_simulate.execute(target="8.8.8.8:8088") is False

    def test_unknown_scenario_fails_cleanly(self):
        assert splunk_simulate.execute(target="127.0.0.1:8088", scenario="bogus") is False

    def test_successful_simulation_saves_result(self, tmp_path, monkeypatch):
        import toolkit.state as state
        monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")
        monkeypatch.setattr(splunk_simulate, "EVENT_LOG_DIR", tmp_path / "events")
        monkeypatch.setitem(splunk_simulate.DATA_INPUTS['http'], 'token', '')

        assert splunk_simulate.execute(target="127.0.0.1:8088", scenario="persistence") is True

        result = state.load_latest_result("soc", "splunk", operations=("simulate",))
        assert result is not None
        assert result["total_events"] == splunk_simulate.ATTACK_SCENARIOS["persistence"]["events"]
