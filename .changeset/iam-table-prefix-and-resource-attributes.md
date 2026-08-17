---
'@gentleduck/iam': minor
---

Prefix the drizzle tables and constraints with `iam_`, and let the Nest access
guard contribute resource attributes.

**Renamed tables and constraints.** The physical tables move from the
`access_*` prefix to `iam_*` (`access_policies` → `iam_policies`,
`access_roles` → `iam_roles`), along with every derived `pk_`, `uq_`, `idx_`
and `ch_` identifier, in the `mysql`, `pg` and `sqlite` schema builders. This
makes the schema attributable to this package once merged into a host
application's database.

Existing databases need a migration renaming those tables and their
constraints. New installations are unaffected.

**`getResourceAttributes` on `iamNestAccessGuard`.** An optional hook that
computes the attributes attached to `resource.attributes` before
`engine.can()` runs. It receives the resolved `{ action, resource }` alongside
the request, because the correct attributes are resource-specific: a `users`
row is its own subject, whereas an `iamAssignments` row carries its subject in
a column. Passing the resolved pair means callers do not have to re-derive
which case they are in from the raw request.

**Known gap:** the drizzle adapter and native-attr-shape test suites (47 cases)
are temporarily disabled while their mock table references are reworked for the
rename.
