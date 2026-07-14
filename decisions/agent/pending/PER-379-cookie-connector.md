# PER-379: Use an explicit Chrome cookie connector

## Status

Pending human review; approved in conversation for implementation.

## Decision

Use a private Manifest V3 Chrome extension to transfer the consented user's LinkedIn cookie jar to Railway only after an explicit Connect action. Request only the `cookies` capability and LinkedIn/Railway host access needed for the operation and serialize transfers. Remove cookie/LinkedIn access before upload, remove the site scope after encrypted storage responds, and clear residual scopes on worker startup. Do not pre-grant access, poll for cookie changes, or collect in the background.

Commit a public manifest key so the side-loaded development extension keeps the stable ID `ohjgceimoldkhlncabhahccapgoolknc`; Railway can then enforce one exact extension origin reproducibly. This key is public identity material and is not used to sign session data.

The website issues a hashed, single-use pairing token with a ten-minute expiry. The extension sends cookies once over HTTPS. Railway encrypts and persists only ciphertext, returns promptly so extension cleanup is not coupled to LinkedIn latency, and the website immediately starts the separate authentication/self-profile probe.

Commit the exact production `PUBLIC_BASE_URL` allow-list before side-loading.
The friend uses `extension/` from the same clean commit recorded by the gate;
uncommitted per-install edits are not acceptable evidence.

## Consequences

- A normal web page cannot read LinkedIn HttpOnly cookies; the extension is required for the no-copy experience.
- The side-loaded extension is acceptable for the one-friend MVP; store distribution is deferred.
- A stolen cookie can grant account access, so logs, fixtures, errors, and API responses must be demonstrably secret-free.

## Links

- Ticket: PER-379
- Parent: PER-377
