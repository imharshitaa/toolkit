"""
Trivy Reporting Module
Renders the most recent scan result into HTML or Markdown.
"""
from pathlib import Path

from toolkit.reporting import ReportDataError, filter_by_severity, render_report
from toolkit.state import load_latest_result
from toolkit.utils import logger


def execute(**kwargs) -> bool:
    output_path = Path(kwargs.get('output_path', 'reports/trivy_report.html'))
    fmt = kwargs.get('format', 'html')
    severity_filter = kwargs.get('severity_filter', 'all')

    result = load_latest_result('vm', 'trivy', operations=('scan',))
    if not result:
        logger.error("No prior Trivy scan found. Run 'toolkit scan vm trivy --target <path-or-image>' first.")
        return False

    result = dict(result)
    result['findings'] = filter_by_severity(result.get('findings', []), severity_filter)

    try:
        path = render_report(result, output_path, fmt=fmt)
    except ReportDataError as e:
        logger.error(str(e))
        return False

    logger.info(f"Report written to {path}")
    return True
