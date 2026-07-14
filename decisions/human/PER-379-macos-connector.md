# PER-379: Use a downloadable macOS connector

## Status

Approved by the user on 2026-07-14.

## Decision

Replace the side-loaded Chrome extension as the active acquisition path with a
downloadable macOS connector for the invited friend. The website creates a
hashed, single-use pairing token with a ten-minute expiry and packages the raw
token only inside an ephemeral download. The connector opens an isolated,
temporary Chrome profile, waits for the user to sign into LinkedIn, reads the
applicable LinkedIn cookie jar through Chrome's local DevTools protocol, and
posts it directly to Railway over HTTPS.

Never display, copy, log, or persist LinkedIn cookie values on the client. The
connector deletes its token-bearing launcher and temporary Chrome profile on
exit. Railway validates and AES-256-GCM encrypts the cookie payload before
SQLite persistence, exactly as in the original feasibility gate.

Use the installed stable Chrome binary without fingerprint changes, proxying,
challenge bypass, or a hosted browser. Chrome must use a non-default
`--user-data-dir`; Chrome 136 and later deliberately reject remote debugging of
the default profile. Stop normally if the user closes the connector, login does
not complete within ten minutes, or the pairing expires.

For the one-friend MVP, distribute an executable `.command` file inside a ZIP so
Finder preserves its executable bit. The launcher may require an existing
Python 3 installation and must show a specific recovery message when it is
absent. A signed and notarized standalone Mac app is deferred until broader
distribution is justified.

## Consequences

- A website still cannot read LinkedIn HttpOnly cookies; the local connector is
  the explicit, user-run bridge.
- The raw pairing token is short-lived and single-use but remains sensitive
  until consumed; it must not appear in URLs, logs, API JSON, process arguments,
  or terminal output.
- The side-loaded extension is removed from the active product surface, and
  `EXTENSION_ID` is no longer a required deployment setting.
- The Railway replay feasibility gate and all terminal stop conditions remain
  unchanged.

## Links

- Ticket: PER-379
- Parent: PER-377

