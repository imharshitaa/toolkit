# Tests

Unit test suite for ToolKit. Run from the repository root:

```bash
pip install -r requirements-dev.txt
pytest -v
```

**Last verified result: 102 passed, 0 failed, 0 skipped.**

## What's covered directly (no mocking required)

These run real code against real inputs — no external binary, daemon, or network
access involved:

| File | Covers |
|---|---|
| `test_iacauditor.py` | IaC Auditor's Terraform/Compose regex scanning against fixture files (both known-bad and clean inputs) |
| `test_llmriskscanner.py` | LLM Risk Scanner's pattern matching against fixture transcripts, including the sensitive-data masking logic |
| `test_security.py` | `toolkit.security.require_authorized_target` — private targets pass, public targets are rejected without `--i-have-authorization`, accepted with it |
| `test_state.py` | `toolkit.state` save/load round-trip, most-recent-result selection across operations |
| `test_reporting.py` | `toolkit.reporting.render_report` — real HTML/Markdown output from fixture data, severity filtering, empty-findings placeholder |
| `test_cli.py` | Click command wiring — `version`, `status`, `list-tools`, `deploy --help`, argument validation |

## What's covered with mocking

These exercise the real module logic (parsing, validation, error handling) with the
external dependency replaced by a mock, since the binary/daemon isn't guaranteed to
be present in every development or CI environment:

| File | Mocks | Covers |
|---|---|---|
| `test_nmap.py` | `subprocess.run`, `shutil.which` | XML parsing of real nmap output format, missing-binary handling, timeout handling, non-zero exit handling |
| `test_trivy.py` | `subprocess.run`, `shutil.which` | JSON parsing of real Trivy report format, same error paths as nmap |
| `test_zap.py` | `requests.get` | ZAP REST API flow (spider → active scan → alerts), quick vs. full scan profile behavior, unreachable-daemon handling |
| `test_splunk_simulate.py` | `requests.post` | Attack-scenario event generation, HEC delivery with local-log fallback (no token configured, HEC unreachable) |
| `test_wazuh_deploy.py` | `docker.from_env` | Config validation, dry-run path (asserts Docker is never touched), container health inspection across running/not-found/daemon-unreachable states |

## What is not covered by this suite

Stated explicitly rather than silently skipped:

- **Live nmap/Trivy scans** — the binaries are not installed in every environment;
  only their output *parsers* are tested, against representative XML/JSON fixtures.
- **Live Docker deploys** (ZAP daemon, Wazuh stack, Splunk Docker container) — the
  Docker SDK is mocked; container startup, networking, and image pulls are not
  exercised against a real daemon in this suite.
- **Live AWS/Kubernetes deploys** — `modules/SOC/splunk/deploy.py`'s `deploy_aws`
  and `deploy_kubernetes` paths require real cloud/cluster credentials this project
  does not have; they are not under test.
- **Full multi-container Splunk/Wazuh stacks** — these are multi-GB downloads and
  slow to start even where Docker works; see `tests/test_wazuh_deploy.py` for what
  *is* covered of that path (config validation, dry-run, health-check parsing).

## Patterns used

- `monkeypatch.setattr(state, "STATE_DIR", tmp_path / ".toolkit_state")` isolates
  every test's state-file I/O to a temp directory — no test writes to the real
  `.toolkit_state/`.
- `unittest.mock.patch` / `MagicMock` replace `subprocess.run`, `shutil.which`,
  `requests.get`/`post`, and `docker.from_env` where a real external dependency
  would make the test slow, flaky, or environment-dependent.
- Fixture data (sample nmap XML, sample Trivy JSON, sample Terraform/Compose text,
  sample transcripts) lives inline in each test file next to the tests that use it.
