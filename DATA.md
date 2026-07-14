# DATA.md

- `/app/data/linkedin_finder.sqlite3` — private Railway runtime database; schema and retention details: `docs/data/linkedin_finder_sqlite.md`.
- `/app/data/reproduction.txt` — sanitized runtime recipe containing commit and schema versions; generated at application startup.
- Downloaded `LinkedIn-Connector*.zip` packages — ephemeral, token-bound macOS connector downloads generated in memory by the Railway website; never persisted by the service and valid for ten minutes.
