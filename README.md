# LinkedIn Conversation Finder

This fork is building a private, Railway-hosted tool that helps one invited user find people for useful career-exploration conversations. The eventual product combines deterministic LinkedIn profile collection with evidence-backed language-model ranking. Automated outreach is out of scope.

The repository began as [`frizynn/linkedin-cli`](https://github.com/frizynn/linkedin-cli). Its existing terminal client remains the extraction foundation.

## Status

The conversation finder is currently stopped at its Railway authentication feasibility gate. Implemented in this gate:

- Invite-passcode login with a seven-day secure application session
- A side-loaded Manifest V3 connector with one-transfer cookie/host permissions
- Ten-minute, single-use browser pairing
- AES-256-GCM cookie encryption before SQLite persistence
- Sanitized authentication/self-profile probe history
- Railway Docker, volume, health, readiness, and reproduction contracts

Company discovery, profile enrichment, OpenRouter ranking, MCP tools, and the conversational skill are intentionally not implemented yet. They remain blocked until one encrypted session on one exact commit/extractor completes three successful authentication and self-profile probes spanning at least 24 hours and two Railway deployments. Any login/authwall, checkpoint, challenge, schema drift, non-retryable HTTP denial, or session rejection stops the gate; proxying, fingerprint evasion, and hosted-browser fallbacks are prohibited. Both failure and success are terminal until a human makes the post-gate decision.

See the [Railway gate runbook](docs/deployment.md) and [private extension setup](extension/README.md).

## Inherited CLI status

The underlying CLI is early-stage software built around a real LinkedIn web session rather than OAuth.

Verified end-to-end against a live authenticated session:
- `linkedin auth-status`
- `linkedin feed`
- `linkedin profile`

Implemented and covered by tests, but less battle-tested against live LinkedIn sessions:
- `linkedin search`
- `linkedin profile-posts`
- `linkedin activity`
- `linkedin post`
- `linkedin react`
- `linkedin unreact`
- `linkedin save`
- `linkedin unsave`
- `linkedin comment`

## What It Does

Read operations:
- Inspect your authenticated home feed
- Fetch a profile by public identifier or LinkedIn profile URL
- Search people and posts
- Fetch posts from a profile
- Inspect activity details
- Emit machine-readable JSON for scripting

Write operations:
- Publish a post through browser automation fallback
- React or unreact to an activity
- Save or unsave an activity
- Comment on an activity

Auth and runtime support:
- Full `LINKEDIN_COOKIE_HEADER` support
- Minimal `LINKEDIN_LI_AT` and `LINKEDIN_JSESSIONID` support
- Browser cookie extraction from Chrome, Chromium, Brave, Edge, or Firefox
- Optional Playwright browser fallback for fragile write flows
- Proxy support

## Important Notes

- This project is unofficial and is not affiliated with LinkedIn.
- LinkedIn can change internal web endpoints without notice. A command that works today may need adjustment later.
- Session cookies are credentials. Treat them like passwords.
- Do not use this project for spam, scraping at abusive rates, or anything that violates the platform rules that apply to your account.
- Private-cookie automation can result in account restriction under LinkedIn's [User Agreement](https://www.linkedin.com/legal/user-agreement). The finder must never claim platform compliance or exhaustive company coverage.

## Installation

### Install from source

```bash
git clone https://github.com/VishalJ99/linkedin-cli.git
cd linkedin-cli
uv sync
```

### Install as a tool

```bash
uv tool install .
```

Alternative:

```bash
pipx install .
```

Install Playwright browsers if you want browser fallback support for write actions:

```bash
uv run playwright install chromium
```

## Quick Start

### 1. Export your LinkedIn session

The most reliable option is the full cookie header from a logged-in browser session.

```bash
export LINKEDIN_COOKIE_HEADER='li_at=...; JSESSIONID="ajax:..."; bcookie="..."; bscookie="..."; ...'
```

Then verify auth:

```bash
linkedin auth-status
```

Expected outcome for a healthy session:
- `basic-probe=ok`
- `voyager_me=ok:200`
- `voyager_feed=ok:200`
- `voyager_profile=ok:200`

### 2. Read your feed

```bash
linkedin feed --max 10
linkedin feed --max 10 --json
```

### 3. Inspect a profile

```bash
linkedin profile lebrero-juan-francisco
linkedin profile https://www.linkedin.com/in/lebrero-juan-francisco/ --json
```

### 4. Search

```bash
linkedin search "AI engineer" --max 10
linkedin search "MercadoLibre" --max 10 --json
```

## Authentication

Authentication is resolved in this order:

1. `LINKEDIN_COOKIE_HEADER`
2. `LINKEDIN_LI_AT` + `LINKEDIN_JSESSIONID`
3. Browser cookie extraction from a supported local browser

### Recommended: full cookie header

This is the most reliable option for authenticated reads.

One practical way to obtain it:
1. Log into `https://www.linkedin.com` in your browser.
2. Open developer tools.
3. Open the Network tab and reload the page.
4. Select a request to `www.linkedin.com`.
5. Copy the `cookie` request header value.
6. Export it as `LINKEDIN_COOKIE_HEADER`.

```bash
export LINKEDIN_COOKIE_HEADER='li_at=...; JSESSIONID="ajax:..."; ...'
linkedin auth-status
```

### Minimal environment variables

This can be enough for some flows, but it is less reliable than the full cookie jar.

```bash
export LINKEDIN_LI_AT='AQ...'
export LINKEDIN_JSESSIONID='"ajax:123456789"'
```

### Browser cookie extraction

If you are logged into LinkedIn locally, the CLI can try to extract cookies from:
- Chrome
- Chromium
- Brave
- Edge
- Firefox

Optional environment variables:

```bash
export LINKEDIN_BROWSER='chrome'
export LINKEDIN_HEADLESS='1'
export LINKEDIN_PROXY='http://127.0.0.1:7890'
export LINKEDIN_CONFIG="$PWD/config.yaml"
```

## Commands

```bash
linkedin auth-status
linkedin feed --max 20 --json
linkedin search "product manager" --max 10
linkedin profile satyanadella --json
linkedin profile-posts satyanadella --max 20
linkedin activity urn:li:activity:123
linkedin post "hello from linkedin-cli"
linkedin react urn:li:activity:123 --type like
linkedin unreact urn:li:activity:123
linkedin save urn:li:activity:123
linkedin unsave urn:li:activity:123
linkedin comment urn:li:activity:123 "nice post"
```

## Codex Skills

This repository ships public Codex skills in [`skills/`](./skills/):

- `linkedin-cli` for general command selection, read workflows, and JSON export
- `linkedin-cli-auth` for cookies, auth diagnostics, browser extraction, and config
- `linkedin-cli-write` for posting, reacting, saving, unsaving, and commenting

These skills are intended to stay in-repo so anyone cloning the project can reuse the same operational guidance.

## Configuration

The repository includes a sample [`config.yaml`](./config.yaml). The default shape is:

```yaml
fetch:
  count: 20

filter:
  enabled: false
  mode: "recent"

browser:
  preferred: "chrome"
  fallback_enabled: true
  headless: true

rate_limit:
  request_delay: 1.25
  max_retries: 3
  retry_base_delay: 3.0
  write_delay_min: 1.5
  write_delay_max: 4.0
  timeout: 20.0
```

## Development

Set up a local development environment:

```bash
uv sync --extra dev
uv run playwright install chromium
```

Run checks:

```bash
uv run ruff check .
uv run pytest -q
uv run python -m compileall linkedin_cli tests
```

## Testing Philosophy

- Unit tests should not depend on a live LinkedIn session.
- Network-sensitive behavior should be isolated behind transport or browser abstractions and mocked in tests.
- Live-session verification is still useful before releases, especially for auth, feed, and profile flows.

## Security and Privacy

- Never commit cookies, tokens, HAR files, or browser state exports.
- Never paste live `LINKEDIN_COOKIE_HEADER`, `li_at`, or `JSESSIONID` values into issues or pull requests.
- Sanitize screenshots, logs, and terminal transcripts before sharing.

See [`SECURITY.md`](./SECURITY.md) for reporting guidance.

## Contributing

Contributions are welcome. Before opening a pull request, read:
- [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)
- [`SECURITY.md`](./SECURITY.md)
- [`CHANGELOG.md`](./CHANGELOG.md)

## License

This project is released under the [MIT License](./LICENSE).
