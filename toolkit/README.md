# toolkit/ — Core Package

The CLI and shared infrastructure every `modules/` tool is built on. This is the
`toolkit` package installed by `pip install -e .` (entry point: `toolkit.cli:main`).

| File | Responsibility |
|---|---|
| `cli.py` | Click group wiring: `version`, `status`, `list-tools`, and the `deploy`/`scan`/`report`/`open` subcommands |
| `core.py` | `ToolKitCore` — the tool catalog (`get_available_tools()`), dynamic module loading (`importlib.import_module(f"modules.{module.upper()}.{tool.lower()}.{operation}")`), and `execute_operation()` |
| `deploy.py` / `scan.py` / `report.py` / `open_dashboard.py` | The four CLI subcommands — each validates arguments, then calls `core.execute_operation()` |
| `security.py` | `require_authorized_target()` — restricts active scans to loopback/RFC1918 targets unless `--i-have-authorization` is passed |
| `state.py` | `save_result()`/`load_latest_result()` — persists each run's structured output to `.toolkit_state/<module>_<tool>_<operation>.json`, which `report.py` reads back |
| `reporting.py` | `render_report()` — shared Jinja2 HTML/Markdown templates used by every module's `report.py` |
| `utils.py` | `check_dependencies()`, `run_command()`, `get_cloud_credentials()` (reads strictly from environment variables — never hardcoded), validation helpers, custom exceptions |

## How a module is invoked

`toolkit <deploy|scan|report> <module> <tool> [options]` resolves to
`modules.<MODULE_UPPER>.<tool>.<operation>.execute(**kwargs)`. Every tool module
implements `execute()` for whichever operations it supports (deploy/scan/report),
plus a `config.py` exposing `validate()`. See any directory under `modules/` for
the pattern, or the main `README.md`'s Architecture section for the full request
flow diagram.

## Where results live

Nothing is held in memory between commands — every `deploy`/`scan` writes its
result to `.toolkit_state/` (gitignored), and `report` reads the most recent
matching file back. Deleting `.toolkit_state/` just means the next `report` call
will say no prior run was found, rather than fabricating one.
