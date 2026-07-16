# AGENTS.md

## Purpose

This fork builds a private, Railway-hosted LinkedIn conversation-finder for one invited user. It combines deterministic profile collection with evidence-backed language-model ranking for career-exploration conversations. Automated outreach, scraping-evasion infrastructure, and claims of exhaustive LinkedIn coverage are out of scope.

## Active work

- Linear project: `LinkedIn Conversation Finder` (`ac6774363500`). Place every issue for this repository under this project.
- PER-377: parent MVP
- PER-379: direct Cookie-header connection and Railway authentication feasibility gate
- PER-378, PER-380, PER-381: blocked until PER-379 passes three authenticated probes across 24 hours

Stop after PER-379 if Railway receives a login, checkpoint, challenge, or session rejection. Record evidence in Linear; do not add proxies, fingerprint bypasses, or hosted-browser fallbacks. A pass requires one encrypted session and exact commit/extractor across three probes spanning 24 hours and at least two Railway deployment IDs; both pass and failure are terminal pending a human decision.

## Development

- Install: `uv sync --extra dev`
- Test: `uv run pytest -q`
- Lint: `uv run ruff check .`
- Compile: `uv run python -m compileall linkedin_cli tests`
- Keep Python 3.9 compatibility unless a recorded decision changes it.
- Keep commits small. Put the Linear ticket ID on the first line of each commit body.

## Data and security

- Resolve project data through `DATA.md`; details live in `docs/data/`.
- Runtime SQLite is private and must never be committed or DVC-tracked.
- Never log or return LinkedIn cookie values, passcodes, encryption keys, MCP tokens, or OpenRouter keys.
- Encrypt LinkedIn cookie payloads with AES-256-GCM before persistence. Decrypt only in memory for an explicit authenticated operation.
- Cookie submission must be user-initiated through the authenticated, CSRF-protected website; clear the browser field immediately and encrypt before persistence.
- Validate LinkedIn URLs and reject arbitrary hosts.

## Deployment

- Run one Railway web worker against one SQLite volume mounted at `/app/data`.
- Apply SQLite migrations at process startup, not build or pre-deploy time.
- Expose `/healthz` for liveness and `/readyz` for database readiness.
- Persist a sanitized `/app/data/reproduction.txt`; never include secrets.
- Deploy the exact tested revision recorded by the gate before accepting a Cookie header.

## Records

- Record consequential architecture/security choices in `decisions/agent/pending/` for user review.
- Update `DATA.md` when introducing durable runtime or fixture data.
- Add a logbook entry for live Railway/LinkedIn observations; pure engineering work does not need one.
