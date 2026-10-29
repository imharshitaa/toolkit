"""
Tests for toolkit.reporting — the shared HTML/Markdown report renderer used
by every module's report.py.
"""
import pytest

from toolkit.reporting import ReportDataError, filter_by_severity, render_report

SAMPLE_DATA = {
    "tool_name": "Sample Tool",
    "module": "netsec",
    "generated_at": "2026-01-01T00:00:00",
    "summary": "Scanned 1 host, found 2 issues.",
    "findings": [
        {"title": "Open port 22", "description": "SSH open to the world", "severity": "critical"},
        {"title": "Open port 80", "description": "HTTP open", "severity": "low"},
    ],
    "recommendations": ["Close port 22", "Use HTTPS instead of HTTP"],
}


class TestFilterBySeverity:
    def test_all_keeps_everything(self):
        assert filter_by_severity(SAMPLE_DATA["findings"], "all") == SAMPLE_DATA["findings"]

    def test_empty_minimum_keeps_everything(self):
        assert filter_by_severity(SAMPLE_DATA["findings"], "") == SAMPLE_DATA["findings"]

    def test_high_minimum_drops_low(self):
        result = filter_by_severity(SAMPLE_DATA["findings"], "high")
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_unknown_minimum_keeps_everything(self):
        result = filter_by_severity(SAMPLE_DATA["findings"], "not-a-real-severity")
        assert result == SAMPLE_DATA["findings"]


class TestRenderReport:
    def test_render_html(self, tmp_path):
        output = tmp_path / "report.html"
        path = render_report(SAMPLE_DATA, output, fmt="html")
        assert path == output
        content = output.read_text()
        assert "Sample Tool" in content
        assert "Open port 22" in content
        assert "Close port 22" in content

    def test_render_markdown(self, tmp_path):
        output = tmp_path / "report.md"
        path = render_report(SAMPLE_DATA, output, fmt="markdown")
        content = path.read_text()
        assert "# Sample Tool Security Report" in content
        assert "Open port 22" in content

    def test_render_creates_parent_dirs(self, tmp_path):
        output = tmp_path / "nested" / "dir" / "report.html"
        path = render_report(SAMPLE_DATA, output, fmt="html")
        assert path.exists()

    def test_empty_findings_renders_placeholder(self, tmp_path):
        data = {**SAMPLE_DATA, "findings": [], "recommendations": []}
        path = render_report(data, tmp_path / "report.html", fmt="html")
        assert "No findings recorded" in path.read_text()

    def test_no_data_raises(self, tmp_path):
        with pytest.raises(ReportDataError):
            render_report({}, tmp_path / "report.html")
