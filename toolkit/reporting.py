"""
ToolKit Shared Reporting Engine
Renders a standard result record (produced by any module's scan/simulate/deploy
operation and persisted via toolkit.state) into HTML or Markdown. Centralizing
this means every module's report.py stays a thin wrapper instead of
reimplementing formatting.
"""
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{{ tool_name }} Security Report</title>
    <style>
        body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 40px; color: #1a1a1a; }
        h1 { margin: 0; }
        .header { background: #1b2838; color: #fff; padding: 20px 24px; border-radius: 6px; }
        .meta { color: #cbd5e1; font-size: 0.9em; margin-top: 6px; }
        .section { margin: 24px 0; padding: 20px; border: 1px solid #e2e8f0; border-radius: 6px; }
        .finding { margin: 12px 0; padding: 12px 14px; border-radius: 4px; border-left: 4px solid #94a3b8; background: #f8fafc; }
        .critical { background: #fee2e2; border-left-color: #dc2626; }
        .high { background: #ffedd5; border-left-color: #ea580c; }
        .medium { background: #fef3c7; border-left-color: #d97706; }
        .low { background: #dcfce7; border-left-color: #16a34a; }
        .info { background: #e0f2fe; border-left-color: #0284c7; }
        .empty { color: #64748b; font-style: italic; }
        .badge { display: inline-block; font-size: 0.75em; font-weight: 600; letter-spacing: 0.03em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ tool_name }} Security Report</h1>
        <div class="meta">Module: {{ module|upper }} &middot; Generated: {{ timestamp }}</div>
    </div>

    <div class="section">
        <h2>Summary</h2>
        <p>{{ summary }}</p>
    </div>

    <div class="section">
        <h2>Findings ({{ findings|length }})</h2>
        {% for finding in findings %}
        <div class="finding {{ finding.severity|default('info') }}">
            <span class="badge">{{ finding.severity|default('info')|upper }}</span>
            <strong>{{ finding.title }}</strong>
            <p>{{ finding.description }}</p>
        </div>
        {% else %}
        <p class="empty">No findings recorded.</p>
        {% endfor %}
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        {% if recommendations %}
        <ul>
        {% for rec in recommendations %}
            <li>{{ rec }}</li>
        {% endfor %}
        </ul>
        {% else %}
        <p class="empty">No recommendations recorded.</p>
        {% endif %}
    </div>
</body>
</html>
"""

MARKDOWN_TEMPLATE = """# {{ tool_name }} Security Report

**Module:** {{ module|upper }}
**Generated:** {{ timestamp }}

## Summary

{{ summary }}

## Findings ({{ findings|length }})
{% for finding in findings %}
### {{ finding.title }} — {{ finding.severity|default('info')|upper }}

{{ finding.description }}
{% else %}
_No findings recorded._
{% endfor %}
## Recommendations
{% if recommendations %}
{% for rec in recommendations %}
- {{ rec }}
{% endfor %}
{% else %}
_No recommendations recorded._
{% endif %}
"""


class ReportDataError(Exception):
    """Raised when there is no usable data to build a report from."""


def filter_by_severity(findings: List[Dict[str, Any]], minimum: str) -> List[Dict[str, Any]]:
    """Keep only findings at or above the given severity (e.g. 'high' keeps critical+high)."""
    if not minimum or minimum == "all":
        return findings
    if minimum not in SEVERITY_ORDER:
        return findings
    cutoff = SEVERITY_ORDER.index(minimum)
    return [f for f in findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= cutoff]


def render_report(data: Dict[str, Any], output_path: Path, fmt: str = "html") -> Path:
    """
    Render a standard result record to disk as HTML or Markdown.

    `data` must contain 'tool_name'; 'module', 'timestamp', 'summary', 'findings'
    (list of {title, description, severity}), and 'recommendations' (list of str)
    are optional and default to empty/placeholder values.
    """
    if not data:
        raise ReportDataError("No result data provided to render.")

    context = {
        "tool_name": data.get("tool_name") or data.get("tool", "Unknown Tool"),
        "module": data.get("module", ""),
        "timestamp": data.get("generated_at") or data.get("timestamp", "unknown"),
        "summary": data.get("summary") or "No summary available.",
        "findings": data.get("findings", []),
        "recommendations": data.get("recommendations", []),
    }

    template_str = MARKDOWN_TEMPLATE if fmt in ("markdown", "md") else HTML_TEMPLATE
    content = Template(template_str).render(**context)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)
    return output_path
