---
'@gentleduck/auth': patch
---

Adapter audit: batch outcomes name the rule that refused a row, and a soft-deleted account no longer holds a provider login hostage.

**`Batch.FailureReason` gained `grace-expired` and `email-taken`.** `not-found` was reported for every row a `restoreMany` did not apply, including rows that were found and then refused by the grace window or by an address a live identity had taken since. A caller told `not-found` has no way to learn the id is still there and still restorable once the clash is resolved. Both batch paths were affected — the set-based SQL form and the loop fallback used by the memory and Redis stores. Consumers matching exhaustively on `FailureReason` will need the two new arms.

**A soft-deleted row no longer holds its provider sub.** The cross-identity uniqueness guard counted hidden rows, but `findByProviderSub` ignores them, so a sub could be unreadable and unclaimable at the same time — a deleted account keeping someone's Google login forever. All four adapters now count live rows only, matching what the read side already did.

**`restoreManyReturning` (SQL bridge) returns `{ candidates, restored }`.** Custom `SqlBridge` implementations need updating; the dialects shipped with the package already do. The candidate rows are what let the store report *why* a row did not come back instead of guessing.

`isRestorable` is exported from `@gentleduck/auth/adapters/sql`, so the batch and single-row paths cannot drift about when a grace window has closed.
