# LinkedIn Finder SQLite Database

The Railway service stores private runtime state at `/app/data/linkedin_finder.sqlite3`. Local development defaults to `./data/linkedin_finder.sqlite3` unless `DATABASE_PATH` is set.

## Gate schema

PER-379 introduces the minimum tables needed to decide whether a consented browser session can be replayed from Railway:

- `schema_migrations`: applied application migrations.
- `users`: the single invited application identity.
- `pairing_tokens`: hashed, single-use, ten-minute extension handoffs.
- `linkedin_sessions`: AES-256-GCM ciphertext and non-secret validation metadata.
- `auth_probes`: sanitized auth/profile probe outcomes and timestamps.

Cookie values must never appear in plaintext columns, logs, API responses, fixtures, or `reproduction.txt`. The encryption key is a sealed Railway variable and is not stored in SQLite.

## Runtime settings

- WAL journaling
- foreign keys enabled
- five-second busy timeout
- strict tables
- one application worker

The database and backups contain private user data. They are not source artifacts and must not be committed or DVC-tracked.

