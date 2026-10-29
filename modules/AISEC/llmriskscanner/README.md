# LLM Risk Scanner Module (AI Security)

A pure-Python static scanner for LLM application transcripts and logs — looks
for patterns associated with the OWASP Top 10 for LLM Applications. No external
binary, no model calls, no credentials.

Status: **implemented**.

## What ToolKit automates

| Command | What it does |
|---|---|
| `toolkit scan aisec llmriskscanner --target <file-or-dir>` | Scans a single file, or every `.txt`/`.log`/`.jsonl`/`.json`/`.md` file in a directory |
| `toolkit report aisec llmriskscanner --format html\|markdown` | Renders a report from the most recent scan |

There is no `deploy` operation — this module only reads text files.

## Why this exists

"AI Security" vendor tooling (Lakera, Robust Intelligence, etc.) is commercial
SaaS. This module covers what's achievable with pattern matching against a
transcript you already have — logs from your own LLM application, a chat
export, prompt/response pairs saved during testing — with zero external
dependencies.

## Quick Start

```bash
toolkit scan aisec llmriskscanner --target ./llm-transcripts/
toolkit report aisec llmriskscanner --format markdown
```

## What it checks

`modules/AISEC/llmriskscanner/config.py` defines three pattern categories:

| Category | Severity | Looks for |
|---|---|---|
| `prompt_injection` | `high` | Phrases associated with instruction-override attempts ("ignore previous instructions", "you are now...", etc.) |
| `insecure_output` | `high` | Model output that looks like it's being passed somewhere dangerous unsanitized (e.g., raw SQL/shell/HTML construction from model text) |
| `sensitive_data` | `critical` | AWS access keys, OpenAI API keys, GitHub tokens, PEM private key blocks, credit card numbers, SSNs, explicit password/secret disclosure |

Input is read line by line; for `.jsonl` files, `_extract_text()` pulls the
text content out of each JSON record rather than matching against raw JSON
syntax.

## Sensitive-data masking

When a `sensitive_data` match is found, `_build_snippet()` keeps only the first
4 characters of the matched value and replaces the rest with `*` before
including it in the finding description — so running this scanner against a
transcript containing a real leaked key does not itself create a second copy of
that key in ToolKit's output/report files.

## Findings cap

`MAX_FINDINGS = 200` — if a target produces more matches than that, the scan
stops and the report notes the result was truncated, rather than silently
dropping findings without saying so.

## What this is not

This is **pattern matching, not a trained classifier** — it does not understand
semantic intent, can be evaded by phrasing a prompt injection attempt in a way
that doesn't match the known patterns, and does not call out to any model or
API to make a judgment call. Treat findings as leads to investigate, not a
guarantee of safety or a complete list of every LLM Top 10 issue present.

## Known limitations

- Pattern lists are a fixed, hand-maintained set — they are not exhaustive and
  will miss novel injection phrasing or obfuscated payloads (e.g., base64-
  encoded instructions).
- No support for multi-modal transcripts (image/audio prompts) — text only.
