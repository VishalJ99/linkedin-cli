# PER-379: Use an explicit Chrome cookie connector

## Status

Pending human review; approved in conversation for implementation.

## Decision

Use a private Manifest V3 Chrome extension to transfer the consented user's LinkedIn cookie jar to Railway only after an explicit Connect action. Request only the `cookies` capability and LinkedIn/Railway host access needed for the operation. Do not poll for cookie changes or collect in the background.

The website issues a hashed, single-use pairing token with a ten-minute expiry. The extension sends cookies once over HTTPS. Railway validates them, encrypts them with AES-256-GCM, and persists only ciphertext.

## Consequences

- A normal web page cannot read LinkedIn HttpOnly cookies; the extension is required for the no-copy experience.
- The side-loaded extension is acceptable for the one-friend MVP; store distribution is deferred.
- A stolen cookie can grant account access, so logs, fixtures, errors, and API responses must be demonstrably secret-free.

## Links

- Ticket: PER-379
- Parent: PER-377

