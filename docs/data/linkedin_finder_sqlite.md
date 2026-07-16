# LinkedIn Finder SQLite Database

The gate service stores private runtime state at `/app/data/linkedin_finder.sqlite3` unless `DATABASE_PATH` is explicitly overridden (tests use temporary paths).

## Gate schema

PER-379 introduces the minimum tables needed to decide whether a consented browser session can be replayed from Railway:

- `schema_migrations`: applied application migrations.
- `users`: the single invited application identity and revocable app-session generation.
- `pairing_tokens`: inactive compatibility history from the superseded connector flow;
  no public route creates or consumes these rows.
- `linkedin_sessions`: AES-256-GCM ciphertext and non-secret validation metadata.
- `auth_probes`: sanitized auth/profile outcomes tied to one encrypted-session ID,
  Railway deployment ID, exact Git commit, extractor version, and timestamp.
- `feasibility_gate`: one non-PII operational tombstone. A LinkedIn rejection or
  the third transient failure permanently changes this row to a stopped state;
  qualifying proof changes it to terminal `passed`.

Cookie values must never appear in plaintext columns, logs, API responses, fixtures, or `reproduction.txt`. The encryption key is a sealed Railway variable and is not stored in SQLite.

## Runtime settings

- WAL journaling
- foreign keys enabled
- five-second busy timeout
- secure deletion enabled, followed by a truncating WAL checkpoint after user deletion
- strict tables
- one application worker

`Delete my data` removes the user row and cascades any historical pairing, encrypted
session, and probe records from the live database. It deliberately preserves
the non-PII `feasibility_gate` stop tombstone so a rejected gate cannot be
restarted by deleting the evidence. Logout rotates the user's session
generation; deleting and recreating the user generates a new one, so copied
seven-day app-session cookies cannot be replayed.

The database and backups contain private user data. They are not source
artifacts and must not be committed or DVC-tracked. The web deletion action
cannot modify Railway-managed backups; the owner must apply Railway's backup
retention/deletion controls separately when the user requests complete backup
purging.
