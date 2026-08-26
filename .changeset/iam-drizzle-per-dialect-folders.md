---
'@gentleduck/iam': patch
---

Restructure the drizzle adapter's schema exports into per-dialect folders, matching
`@gentleduck/auth`'s layout.

`@gentleduck/iam/adapters/drizzle/schema/{pg,mysql,sqlite}` is now
`@gentleduck/iam/adapters/drizzle/{pg,mysql,sqlite}`. Each folder also exports a
`{Pg,Mysql,Sqlite}` types namespace (`PolicyRow`, `RoleRow`, `AssignmentRow`, `AttrRow`)
inferred from that dialect's schema, so a consumer pinned to one dialect no longer needs
to import the adapter's cross-dialect union types to get a concrete row shape.

Update imports from `@gentleduck/iam/adapters/drizzle/schema/pg` (etc.) to
`@gentleduck/iam/adapters/drizzle/pg` (etc.).
