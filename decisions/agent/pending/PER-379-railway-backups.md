# PER-379: Resolve the Railway backup plan requirement

## Status

Pending human decision.

## Context

The deployed gate uses a Railway volume for its encrypted LinkedIn session and
SQLite workflow state. The approved MVP plan requires daily Railway-managed
volume backups before the first live cookie-replay probe.

On 2026-07-14, the Railway dashboard for the deployed service reported that
Backups and point-in-time recovery are available only on the Pro plan. The
service is currently on a plan that cannot create or schedule them. No paid
upgrade was authorized, and no LinkedIn cookie was collected.

## Decision required

Choose one of these before the first live probe:

1. Upgrade the Railway workspace to Pro and enable the Daily schedule.
2. Amend the MVP acceptance criteria to proceed without Railway-managed
   backups and explicitly accept loss of the encrypted session and probe state
   if the volume fails.
3. Stop the hosted-cookie feasibility test and remove the Railway resources.

Do not introduce an ad hoc database export by default. It would create another
copy of security-sensitive state and requires a separate retention, encryption,
and deletion design.

## Consequences

- The application deployment is healthy, but the live LinkedIn gate remains
  paused before cookie collection.
- PER-378, PER-380, and PER-381 remain blocked.
- A paid-plan change is an external billing action and must not be inferred
  from the implementation request.

## Links

- Ticket: PER-379
- Parent: PER-377
- Railway project: `0ce04d36-1a63-4d78-9c89-5596d52d8769`
