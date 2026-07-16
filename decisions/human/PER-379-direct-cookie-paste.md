# PER-379: Accept a pasted LinkedIn Cookie header

## Status

Approved by the user on 2026-07-17. This supersedes the downloadable macOS
connector as the active session-acquisition path.

## Decision

The invited friend will copy the `Cookie` request-header value from an
authenticated LinkedIn browser request and paste it into the invite-protected
Railway website. The website accepts the value only through an authenticated,
CSRF-protected POST, validates that it contains the required LinkedIn session
cookies, AES-256-GCM encrypts it before SQLite persistence, and never returns or
logs the value. The browser clears the textarea as soon as submission starts.

After encrypted storage succeeds, the website runs the first feasibility probe
once. Later probes remain explicit user actions. A connected session cannot be
silently replaced; the user must disconnect first.

The old connector and pairing routes are removed from the public application
surface. Historical pairing tables may remain until a later schema migration,
but no active workflow creates or consumes pairing tokens.

## Consequences

- Copying and pasting a Cookie header is less polished and briefly exposes the
  credential in the browser UI and clipboard, but it removes the brittle local
  Chrome-debugging step for this one-friend feasibility test.
- The Cookie header must be treated like a password. It must be pasted only into
  the expected Railway HTTPS origin and cleared from the clipboard after use.
- The existing Railway-origin stop rules, encrypted persistence, deletion
  controls, and prohibition on proxying or evasion remain unchanged.

## Links

- Ticket: PER-379
- Parent: PER-377
