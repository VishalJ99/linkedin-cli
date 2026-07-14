# PER-379: Gate the product on Railway session replay

## Status

Pending human review; approved in conversation for implementation.

## Decision

Do not build company crawling, semantic ranking, or MCP discovery actions until the Railway deployment completes `auth-status` and the consented user's self-profile fetch three times across 24 hours.

On login, checkpoint, challenge, rate-limit, or session rejection, pause the ticket and preserve sanitized evidence. Do not introduce proxying, fingerprint bypasses, scraping evasion, or a hosted-browser fallback.

## Consequences

- PER-378, PER-380, and PER-381 remain blocked behind PER-379.
- The first deployment is intentionally a small feasibility slice rather than a partially built crawler.
- A failed gate may require a new human decision about a local collector architecture.

## Links

- Ticket: PER-379
- Parent: PER-377

