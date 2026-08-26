---
'@gentleduck/auth': patch
---

Drop `deletedAt` from `authCredentials` and `authSessions`, added in 5.3.3. Both
tables' `delete()`/`deleteByKind()`/`deleteAllForIdentity()` are hard-delete by
explicit design (retaining a revoked credential's secret forever, or a dead session
row, is not a feature), so the column would never have been set by anything in this
codebase - it was speculative, not wired to a real soft-delete path. `authCredentials`
already tracks its own dead-state via the adapter-managed `revokedAt`; a second,
adapter-inert "this row is gone" column duplicated that job without adding one.
`authIdentities.deletedAt` is unaffected - its `softDelete(id, gracePeriodMs)` is a
real, adapter-managed flow, unlike these two.
