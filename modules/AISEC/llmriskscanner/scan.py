"""
LLM Risk Scanner
Heuristic, regex-based scan of transcript/log text for OWASP LLM Top
10-style risk patterns: prompt injection, insecure output handling, and
sensitive data exposure. Pattern matching only — not a trained classifier.
"""
import json
from pathlib import Path

from toolkit.state import save_result
from toolkit.utils import logger
from modules.AISEC.llmriskscanner.config import (
    CATEGORIES, CATEGORY_SEVERITY, MAX_FINDINGS, SNIPPET_MAX_LEN,
)

TEXT_EXTENSIONS = {'.txt', '.log', '.jsonl', '.json', '.md'}


def execute(**kwargs) -> bool:
    """
    Args:
        target: path to a transcript/log file, or a directory of them

    Returns:
        bool: Success status
    """
    target = Path(kwargs.get('target', ''))

    if not kwargs.get('target') or not target.exists():
        logger.error("A --target file or directory is required and must exist")
        return False

    files = [target] if target.is_file() else sorted(
        p for p in target.rglob('*') if p.is_file() and p.suffix in TEXT_EXTENSIONS
    )

    if not files:
        logger.error(f"No scannable text/log files found under {target}")
        return False

    findings = []
    for file_path in files:
        findings.extend(_scan_file(file_path))

    truncated = len(findings) > MAX_FINDINGS
    if truncated:
        logger.warning(f"{len(findings) - MAX_FINDINGS} additional finding(s) suppressed (showing top {MAX_FINDINGS})")
        findings = findings[:MAX_FINDINGS]

    logger.info(f"Scanned {len(files)} file(s), {len(findings)} finding(s)")

    save_result('aisec', 'llmriskscanner', 'scan', {
        'tool_name': 'LLM Risk Scanner',
        'summary': f"Scanned {len(files)} file(s) under {target}: {len(findings)} pattern match(es). "
                    "Heuristic pattern matching — review each finding manually before acting on it.",
        'findings': findings,
        'recommendations': [
            'Treat each match as a lead to review manually, not a confirmed incident — this is pattern '
            'matching, not a trained classifier.',
            'For sensitive-data matches, rotate any credential that may have been genuinely exposed.',
            'For prompt-injection matches, confirm whether the input reached the model unsanitized.',
        ] if findings else [],
        'target': str(target),
    })

    return True


def _scan_file(file_path: Path):
    findings = []
    try:
        lines = file_path.read_text(errors='ignore').splitlines()
    except OSError as e:
        logger.warning(f"Could not read {file_path}: {e}")
        return findings

    for line_num, raw_line in enumerate(lines, start=1):
        text = _extract_text(raw_line)
        if not text:
            continue

        for category, patterns in CATEGORIES.items():
            for name, pattern in patterns:
                match = pattern.search(text)
                if not match:
                    continue

                snippet = _build_snippet(text, match, mask=(category == 'sensitive_data'))
                findings.append({
                    'title': f"{name} ({file_path.name}:{line_num})",
                    'description': f"{file_path}:{line_num} — {snippet}",
                    'severity': CATEGORY_SEVERITY[category],
                })

    return findings


def _extract_text(raw_line: str) -> str:
    """Best-effort extraction of human-readable text from a line that may be
    a raw transcript line or a JSONL record with role/content fields."""
    stripped = raw_line.strip()
    if not stripped:
        return ''

    if stripped.startswith('{'):
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        if isinstance(record, dict):
            parts = [str(v) for v in record.values() if isinstance(v, str)]
            return ' '.join(parts)
        return stripped

    return stripped


def _build_snippet(text: str, match, mask: bool) -> str:
    start, end = match.span()
    snippet_text = text[max(0, start - 20):end + 20]
    if mask:
        matched = match.group(0)
        masked = matched[:4] + '*' * max(0, len(matched) - 4) if len(matched) > 4 else '*' * len(matched)
        snippet_text = snippet_text.replace(matched, masked)
    if len(snippet_text) > SNIPPET_MAX_LEN:
        snippet_text = snippet_text[:SNIPPET_MAX_LEN] + '…'
    return snippet_text.strip()
