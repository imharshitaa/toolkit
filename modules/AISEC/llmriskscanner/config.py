"""
LLM Risk Scanner Configuration
Heuristic, regex-based patterns for flagging OWASP LLM Top 10-style risks in
transcript/log text. This is pattern matching, not a trained classifier — it
will have false positives and false negatives, and is intended as a first
pass over logs, not a certification of safety.
"""
import re

# Each pattern: (name, compiled regex, severity). Matches are case-insensitive.
PROMPT_INJECTION_PATTERNS = [
    ('Instruction override attempt', re.compile(r'ignore (all |any )?(previous|prior|above) instructions', re.I)),
    ('Instruction override attempt', re.compile(r'disregard (the )?(system|above) prompt', re.I)),
    ('Role override / jailbreak attempt', re.compile(r'\byou are now (in )?(developer|dan|unrestricted|jailbreak) mode\b', re.I)),
    ('System prompt extraction attempt', re.compile(r'(reveal|print|repeat|show) (your |the )?(system prompt|instructions)', re.I)),
    ('Pretend / roleplay override', re.compile(r'\bpretend (you have |to have )?no (restrictions|rules|guidelines)\b', re.I)),
]

INSECURE_OUTPUT_PATTERNS = [
    ('Unescaped script tag in output', re.compile(r'<script[\s>]', re.I)),
    ('Shell command execution pattern', re.compile(r'\b(os\.system|subprocess\.(run|call|Popen))\s*\(', re.I)),
    ('Raw SQL mutation pattern', re.compile(r'\b(DROP|DELETE FROM|TRUNCATE)\s+TABLE\b', re.I)),
    ('Destructive shell command pattern', re.compile(r'\brm\s+-rf\s+/')),
    ('Code eval pattern', re.compile(r'\beval\s*\(|\bexec\s*\(')),
]

SENSITIVE_DATA_PATTERNS = [
    ('Likely AWS access key', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('Likely OpenAI-style API key', re.compile(r'\bsk-[A-Za-z0-9]{20,}\b')),
    ('Likely GitHub token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b')),
    ('Likely private key block', re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('Likely credit card number', re.compile(r'\b(?:\d[ -]*?){13,16}\b')),
    ('Likely US SSN', re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ('Explicit password/secret disclosure', re.compile(r'\b(password|secret)\s*[:=]\s*\S+', re.I)),
]

CATEGORY_SEVERITY = {
    'prompt_injection': 'high',
    'insecure_output': 'high',
    'sensitive_data': 'critical',
}

CATEGORIES = {
    'prompt_injection': PROMPT_INJECTION_PATTERNS,
    'insecure_output': INSECURE_OUTPUT_PATTERNS,
    'sensitive_data': SENSITIVE_DATA_PATTERNS,
}

MAX_FINDINGS = 200
SNIPPET_MAX_LEN = 120


def validate() -> bool:
    """No external dependency — pure Python pattern matching."""
    return True


def get_config() -> dict:
    return {'categories': list(CATEGORIES.keys())}
