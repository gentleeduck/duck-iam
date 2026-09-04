---
'@gentleduck/auth': patch
---

`AuthEngine.withTransaction(client)` binds the whole public surface - reads included - to a transaction you own, and batch forms report per-row outcomes instead of collapsing to `void`.

The client is opaque to the library and handed straight back to your adapter, so the engine never learns what driver you use. Nested calls inherit it: `flows.completeAccountDeletion()` reaches `identities.softDelete`, `sessions.revokeAllForIdentity` and `credentials.delete`, and all three land on your transaction. Reads are bound too, so a read inside the transaction sees its own uncommitted writes.

Events do not fire inside a transaction. They buffer in `pending` and publish on `flush()`, so a rolled-back deletion never appears in the audit trail as a completed one. `discard()` drops the buffer, `peek()` inspects it without draining, and a listener that throws does not stop the drain - every buffered event is attempted and the call rejects with an `AggregateError` at the end.

Also in this release:

- `identities` gained `softDeleteMany`, `restoreMany`, `eraseMany`, `updateProfileMany`, `linkMany` and `unlinkMany`; `sessions` gained `revokeAllForIdentities` and `revokeByHashes`; the credential store gained `deleteByIdentities`. Each collapses to one statement per table where the adapter can express it and loops otherwise, so every adapter supports every batch form.
- A hard failure - a constraint violation, a driver error - throws, which inside your transaction aborts the whole thing and is what makes a batch atomic with your own work. A soft failure - a lost optimistic-lock race, a row that was not there - is reported per row as `stale-write`, `not-found` or `skipped` without throwing.
- Stores and the drizzle pg, mysql and sqlite bridges declare `withClient`. A store that cannot join a transaction makes `withTransaction` throw `AUTH_MISCONFIGURED` naming that store, rather than silently leaving those writes outside your transaction.
- Guards - `limiter`, `idempotency`, `hijack` and `anomaly` - are deliberately not reachable on the bound view. An attacker who can force a rollback must not be able to refund the attempts it cost.
- `createSqlStores` binds optional bridge methods to their bridge instead of destructuring them, so a bridge implemented as a class no longer loses its `this`.
