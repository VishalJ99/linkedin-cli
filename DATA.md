# DATA.md

- `/app/data/linkedin_finder.sqlite3` — private Railway runtime database; schema and retention details: `docs/data/linkedin_finder_sqlite.md`.
- `/app/data/reproduction.txt` — sanitized runtime recipe containing commit and schema versions; generated at application startup.
- `extension/` — side-loaded Manifest V3 connector source; its exact Railway origin must be committed in the same revision deployed and loaded in Chrome.
