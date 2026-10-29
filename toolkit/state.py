"""
ToolKit Run State
Persists structured results from scan/simulate/deploy operations to local JSON
files, so `toolkit report` can render real data instead of placeholder content.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

STATE_DIR = Path(".toolkit_state")


def _state_path(module: str, tool: str, operation: str) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return STATE_DIR / f"{module.lower()}_{tool.lower()}_{operation.lower()}.json"


def save_result(module: str, tool: str, operation: str, data: Dict[str, Any]) -> Path:
    """Persist a structured operation result for later reporting."""
    path = _state_path(module, tool, operation)
    payload = {
        "module": module,
        "tool": tool,
        "operation": operation,
        "generated_at": datetime.now().isoformat(),
        **data,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    return path


def load_latest_result(
    module: str,
    tool: str,
    operations: tuple = ("scan", "simulate", "deploy"),
) -> Optional[Dict[str, Any]]:
    """Load the most recently recorded result for a tool across its known operations."""
    latest = None
    for operation in operations:
        path = _state_path(module, tool, operation)
        if not path.exists():
            continue
        with open(path) as f:
            result = json.load(f)
        if latest is None or result["generated_at"] > latest["generated_at"]:
            latest = result
    return latest
