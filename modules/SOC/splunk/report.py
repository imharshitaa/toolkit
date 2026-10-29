"""
Splunk Reporting Module
Renders the most recent scan/simulate/deploy result into HTML or Markdown.
"""
from pathlib import Path

from toolkit.reporting import ReportDataError, filter_by_severity, render_report
from toolkit.state import load_latest_result
from toolkit.utils import logger


def execute(**kwargs) -> bool:
    """
    Args:
        output_path: destination file path
        format: 'html' or 'markdown'
        severity_filter: minimum severity to include ('all', 'critical', ... 'low')

    Returns:
        bool: Success status
    """
    output_path = Path(kwargs.get('output_path', 'reports/splunk_report.html'))
    fmt = kwargs.get('format', 'html')
    severity_filter = kwargs.get('severity_filter', 'all')

    result = load_latest_result('soc', 'splunk')
    if not result:
        logger.error("No prior Splunk scan/simulate/deploy result found. Run one first, e.g. "
                      "'toolkit scan soc splunk --simulate' or 'toolkit deploy soc splunk'.")
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
