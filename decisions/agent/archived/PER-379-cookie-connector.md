# PER-379: Use an explicit Chrome cookie connector

## Status

Superseded on 2026-07-14 by
`decisions/human/PER-379-macos-connector.md` before any LinkedIn cookie was
collected or any LinkedIn request was made.

## Prior decision

Use a private Manifest V3 Chrome extension to transfer the consented user's
LinkedIn cookie jar to Railway only after an explicit Connect action. Request
only the cookie and host permissions required for that one transfer, then remove
them immediately.

## Superseding reason

The invited friend is on macOS, and the user selected a website-distributed
local connector to avoid side-loading or Chrome Web Store review. The local
connector preserves the same explicit action, single-use pairing token,
encrypted Railway storage, and feasibility stop rules.

## Links

- Superseding decision: `decisions/human/PER-379-macos-connector.md`
- Ticket: PER-379
- Parent: PER-377

