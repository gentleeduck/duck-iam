---
'@gentleduck/auth': patch
---

Round out audit columns on the drizzle schema (pg/mysql/sqlite):

- `authCredentials`/`authSessions` gain `updatedBy` and `deletedAt` (they already had
  `updatedAt` from a prior release) - both rows are genuinely mutated in place
  (`rotate`/`patchMetadata`/`revoke`, session `update()`), so tracking who/whether
  matters there.
- `authEvents` drops the `createdBy` it briefly had - it's an append-only audit log,
  never updated, so the only actor-relevant fact is who triggered the event, which
  already lives in the event payload itself.

Every read method (`findById`, `listByIdentity`, `findByProviderSub`,
`findByHashedSecret` on credentials; `findByHash`, `listByIdentity` on sessions) now
filters `deletedAt IS NULL`, matching `authIdentities`. Nothing in this adapter sets
`deletedAt` on these two tables (`delete()`/`deleteByKind()`/`deleteAllForIdentity()`
still hard-delete, on purpose - turning them into soft-deletes would mean revoked
credential secrets are retained forever, which is a regression, not a feature); the
column is honored if something outside the adapter sets it.
