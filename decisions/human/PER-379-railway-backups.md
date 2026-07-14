# PER-379: Proceed without Railway-managed backups

## Status

Approved by the user in conversation on 2026-07-14.

## Decision

Retain the Railway volume mounted at `/app/data`, but proceed with the
one-person authentication feasibility test without upgrading the Railway
workspace for managed Backups or point-in-time recovery.

The volume remains required so the encrypted LinkedIn session, pairing state,
probe history, and terminal gate result survive deployments. The user accepts
that this state may be lost if the volume itself fails.

Do not create an ad hoc export of the private SQLite database. That would add a
second copy of security-sensitive state without an approved encryption,
retention, and deletion design.

## Consequences

- The paid backup-plan blocker is resolved for the MVP gate.
- The live pairing/probe may proceed after the deployed website and exact
  side-loaded extension commit are verified.
- A volume failure may require starting the gate again with a new encrypted
  session and explicit consent.
- PER-378, PER-380, and PER-381 remain blocked until the three-probe Railway
  authentication gate itself passes.

## Links

- Ticket: PER-379
- Parent: PER-377
- Railway project: `0ce04d36-1a63-4d78-9c89-5596d52d8769`
