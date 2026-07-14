# PER-379: Gate the product on Railway session replay

## Status

Approved by the user in the implementation plan on 2026-07-14.

## Decision

Do not build company crawling, semantic ranking, or MCP discovery actions until
the Railway deployment completes `auth-status` and the consented user's
self-profile fetch three times across 24 hours. All three successes must belong
to one encrypted LinkedIn session, exact Git commit, and extractor version, and
must cover at least two Railway deployment IDs.

On login/authwall, checkpoint, challenge, schema drift, rate-limit,
non-retryable HTTP denial, or session rejection, pause the ticket and preserve
sanitized evidence. Do not introduce proxying, fingerprint bypasses, scraping
evasion, or a hosted-browser fallback.

Persist a non-PII stop tombstone outside the deletable user-data relationship.
The third transient failure also stops the gate. This prevents deletion,
re-pairing, or process restart from silently resetting a failed feasibility
decision.

Persist `passed` as a terminal state as well. Disable further pairing and probe
requests once proof passes, and prevent an active session from being replaced
without an explicit Disconnect that resets session-bound progress.

## Consequences

- PER-378, PER-380, and PER-381 remain blocked behind PER-379.
- The first deployment is intentionally a small feasibility slice rather than
  a partially built crawler.
- A failed gate may require a new human decision about a local collector
  architecture.

## Links

- Ticket: PER-379
- Parent: PER-377
