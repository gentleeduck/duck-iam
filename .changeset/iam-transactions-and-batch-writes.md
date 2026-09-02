---
'@gentleduck/iam': patch
---

`IamEngine.withTransaction(client)` binds reads and writes to a transaction you own, and `admin` gained batch forms that report per-row outcomes.

The client is opaque to the library and handed straight back to your adapter. Writes go through `.admin`, the same interface as `engine.admin`, so there is one write surface rather than two. Reads on the bound view run against caches created for that transaction alone: an empty cache always misses through to the transaction-bound adapter, which is what makes a read-after-write inside the transaction correct, and the shared engine keeps answering from its own warm caches, which the transaction never pollutes.

Cache invalidations - including the `config.invalidator` fleet broadcast - buffer in `pending`, de-duplicated, and fire on `flush()`. A rolled-back grant therefore never evicts another node's cache for a write that did not happen. The bound view drops the invalidator rather than reusing the parent's, so a facade built per transaction cannot leak a subscription; buffered entries broadcast through the parent engine on flush.

Also in this release:

- `admin` gained `assignRoles`, `revokeRoles`, `moveRoleScopes` and `invalidateSubjects`. Every row is validated before any is written, so a malformed row aborts the batch instead of half-applying it, and each affected subject is invalidated once however many rows named it.
- Both role writes are idempotent, so every row is `ok` - granting a role a subject already holds is success, matching the single-row method. Outcomes carry `changed` for the finer answer: `true` when this call wrote the row, `false` when it was already in the requested state, and absent where the adapter could not say. It is read off a `RETURNING` clause on the write itself, so it costs no extra round trip; MySQL, which has no `RETURNING`, and adapters that loop the `void`-returning single-row methods leave it off rather than guess.
- The drizzle adapter collapses the writes into one `INSERT` and one `DELETE`. The `DELETE` needs `or` in the adapter's `ops` and revokes row by row without it.
- The adapter contract gained an optional `withClient`. An adapter that cannot join a transaction makes `withTransaction` throw rather than silently leaving those writes outside it.
