---
'@gentleduck/iam': minor
---

Add `engine.admin.updateAssignmentScope(subjectId, roleId, fromScope, toScope, actor?)`
to move a role assignment to a different scope in one write instead of
revoke + assign.

`IamAdapter.ISubjectStore` gains an optional `updateAssignmentScope`. When an adapter
implements it, the engine uses it directly; when it doesn't (or it returns `false`
because nothing matched `fromScope`), the engine transparently falls back to
revoke + assign, so the call always succeeds either way.

Implemented for `memory`, `file`, `prisma`, and `drizzle`. `drizzle` additionally needs
`ops.isNull` configured (matching `deletedAt` filtering) to match the global/unscoped
case correctly; without it, `updateAssignmentScope` returns `false` and the engine falls
back automatically. Not implemented for `redis` (scope is encoded into the Set member
itself, so there's no cheaper path than remove + add) or `http` (would need a new
endpoint on the operator's server) - both already work correctly via the fallback.

`iamAssignments` gains `updatedAt`/`updatedBy` in the drizzle schema (pg/mysql/sqlite)
to support this - the only table getting them in this release, since it's now the only
one with a real update path that didn't already have them.
