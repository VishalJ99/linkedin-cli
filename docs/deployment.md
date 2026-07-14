# Railway authentication feasibility gate

This runbook deploys only the PER-379 authentication gate. It is not approval
to build company discovery, candidate enrichment, ranking, MCP, proxying,
fingerprint evasion, or a hosted browser. Those features remain blocked until
the gate passes exactly as defined below.

## Deployment contract

- Railway runs `linkedin_cli.web:create_app` through Uvicorn with exactly one
  worker. SQLite is not safe here with multiple application workers.
- Mount one persistent Railway volume at `/app/data`. The database is
  `/app/data/linkedin_finder.sqlite3`.
- The application factory initializes and migrates SQLite during process
  startup, after the volume is mounted. Do not add a build-time or Railway
  pre-deploy migration command.
- `GET /healthz` is the process liveness check. `GET /readyz` confirms that
  startup initialization completed and the database is usable.
- Startup writes a sanitized `/app/data/reproduction.txt`. It may contain the
  commit, schema/extractor versions, ticket, and non-secret settings, but never
  cookies, passcodes, keys, tokens, or their hashes.

The Docker build installs the exact `uv.lock` resolution with `uv sync
--frozen`. Local `.env` files, databases, keys, and packaged extensions are
excluded from its build context and are not copied into the image.

## Railway resources

Create one Railway project/service from this repository and configure:

1. A persistent volume mounted at exactly `/app/data`.
2. A public HTTPS domain for the service.
3. Daily backups in the volume's **Backups** settings. This is a manual
   Railway dashboard step; verify that a backup schedule is shown before the
   live probe.
4. One replica. Do not horizontally scale this SQLite service.

Railway supplies `PORT`; do not set it yourself. `railway.toml` uses `/healthz`
as the deployment health check. The volume must be attached at runtime rather
than during the image build or a pre-deploy command.

## Runtime variables

Set variables in Railway's encrypted variable UI. Do not put values in
`railway.toml`, the Dockerfile, a committed `.env` file, shell history, ticket
comments, or logs.

| Variable | Required value/meaning |
| --- | --- |
| `APP_ACCESS_PASSWORD_HASH` | Argon2 hash of the one friend's invite passcode. |
| `APP_SESSION_SECRET` | Independent high-entropy secret used to sign seven-day app sessions. |
| `COOKIE_ENCRYPTION_KEY` | URL-safe base64 encoding of exactly 32 random bytes for AES-256-GCM. |
| `PUBLIC_BASE_URL` | Exact Railway HTTPS origin, without a trailing slash. |
| `EXTENSION_ID` | `ohjgceimoldkhlncabhahccapgoolknc`, derived from the committed public manifest key. |
| `DATABASE_PATH` | `/app/data/linkedin_finder.sqlite3` (also the image default). |
| `APP_USER_ID` | Stable invited-user ID; use `friend` for the gate unless deliberately changed. |
| `APP_COMMIT_SHA` | Full Git SHA from `git rev-parse HEAD`; required for CLI-upload deploys. GitHub deploys may supply `RAILWAY_GIT_COMMIT_SHA` instead. |

Generate each secret independently. These commands prompt for or print a new
value locally; paste the result directly into Railway, then clear the terminal
if its history is retained:

```bash
python -c 'from argon2 import PasswordHasher; import getpass; print(PasswordHasher().hash(getpass.getpass("Invite passcode: ")))'
python -c 'import secrets; print(secrets.token_urlsafe(48))'
python -c 'from linkedin_cli.security import generate_cookie_key; print(generate_cookie_key())'
```

OpenRouter and MCP variables are intentionally absent from this gate. Add them
only after PER-379 passes and the blocked implementation tickets resume.

Do not configure `LINKEDIN_PROXY` for this service. The gate rejects that
setting, and its HTTP transport ignores process-level proxy environment
variables. A passing request must use Railway's own outbound network path.

## Bind the extension to the audited deployment

Railway must assign the public domain before the live extension can be final.
After generating that domain, replace the empty production allow-list in
`extension/config.js` with only its exact origin. Production manifest/config
must contain no localhost origin. Do not side-load an ad hoc edited copy. Commit and push
that configuration, run the extension tests, and use that clean commit for
both `APP_COMMIT_SHA` and `railway up`:

```bash
uv run pytest -q tests/test_extension_manifest.py
node --check extension/service-worker.js
git status --short
git commit -am "Bind the connector to the Railway gate origin" -m "PER-379"
git push
export APP_COMMIT_SHA="$(git rev-parse HEAD)"
railway variables --set "APP_COMMIT_SHA=$APP_COMMIT_SHA" --skip-deploys
```

The friend must side-load `extension/` from that exact clean commit. Record the
commit and extension ID in PER-379. Chrome permission is requested during each
explicit transfer. Cookie and LinkedIn access is removed before upload; the
site-origin permission is removed after the encrypted-storage response, and
worker startup clears residual scopes before accepting messages. The website
preflights that cleanup with a non-sensitive readiness message before enabling
Connect, then starts the first probe separately after storage. There is no
pre-grant or background fallback. If Chrome does not accept the website-click
activation path, record the failure and stop.

## Deploy and smoke-test

Run from a clean checkout of the exact commit being tested:

```bash
git status --short
railway login
railway link
railway up --detach
railway logs
```

After Railway reports the deployment healthy, exercise both endpoints from a
different network path:

```bash
export BASE_URL='https://replace-with-the-railway-domain.example'
curl --fail --silent --show-error "$BASE_URL/healthz"
curl --fail --silent --show-error "$BASE_URL/readyz"
```

Both requests must return a success status. Confirm in Railway that the service
has one replica and the volume is mounted at `/app/data`. Log in through the
website, perform the explicit one-click extension pairing, and confirm that the
UI reports an encrypted LinkedIn session. Inspect application logs only for
sanitized status records; cookie names may appear, but cookie values, pairing
tokens, app sessions, passcodes, encryption keys, and database ciphertext must
not.

Redeploy the same commit once and repeat `/readyz`. Railway's
`RAILWAY_DEPLOYMENT_ID` must change while `APP_COMMIT_SHA` remains identical.
The session status and probe history must still be present after restart, proving that the service used the
volume rather than container-local storage. Verify that
`/app/data/reproduction.txt` exists through the application's sanitized status
or an authenticated Railway shell; never paste the private database into a
ticket or local checkout.

## Strict three-probe gate

The friend must consent to the live test. Start with the authentication-only
gate; do not start even the `20 / 5 / 2` collection test yet.

For each probe, use the website's explicit authenticated action and require
both:

1. authenticated LinkedIn status succeeds from the Railway-origin request; and
2. the friend's own LinkedIn profile is fetched and parsed successfully.

The gate performs exactly those two LinkedIn reads: one `/me` authentication
read and one own-profile page read. It does not repeat `/me` or require feed
access; the inherited CLI's broader diagnostics are outside this gate.

Run three successful probes with the first and third timestamps at least 24
hours apart. Include a redeploy between probes so persistence is covered. A
passing record therefore contains three successful database probe rows, spans
at least 24 hours, uses one encrypted-session ID, exact Git commit, and
extractor version, and contains at least two Railway deployment IDs. Record
only sanitized timestamps, status/kind, commit, deployment count, and endpoint
outcomes in PER-379.

The gate does **not** pass after one or two successes, three successes inside a
24-hour window, local-machine requests, fixture requests, or a successful
cookie upload without the own-profile fetch.

### Immediate stop rule

If any Railway-origin request receives a LinkedIn login/authwall response,
checkpoint, challenge, session rejection, schema drift, any `4xx`, or another
non-`5xx` HTTP denial—including `401`, `403`, `429`, and LinkedIn `999`—stop
the live gate immediately.
Preserve sanitized evidence in SQLite and PER-379, and leave
PER-378, PER-380, and PER-381 blocked. Do not retry around the restriction and
do not add proxies, IP rotation, fingerprint manipulation, browser automation,
hosted-browser infrastructure, or other evasion.

Transient transport failures or LinkedIn `5xx` responses are not evidence that
cookie replay works. The application permits three failed attempts total, not
three retries after an initial failure; the third failure permanently stops
the gate. They never count as successful probes.

`Delete my data` securely removes live user, pairing, session, and probe rows,
but retains the non-PII stop tombstone. Railway-managed backups are outside the
web application's reach; honor a complete deletion request by removing the
relevant backups or project according to the configured Railway retention
controls.

Only after all three qualifying probes pass may the user explicitly authorize
resuming the blocked tickets and the consented `20 / 5 / 2` collection test.
The application persists `passed` as a terminal gate state and disables further
pairing/probe requests. While proof is in progress, a connected session cannot
be silently replaced; an intentional restart requires Disconnect and loses the
old session's qualifying progress.
