---
'@gentleduck/iam': minor
---

The Prisma adapter no longer invents keys a stored role does not have.

`toRole` mapped an absent or null `inherits` column to `inherits: []`, so a role
read back through Prisma was not the role the other adapters returned for the
same row — a caller distinguishing "inherits nothing" from "does not declare
inheritance" saw the two collapse, and only on this adapter. Absent columns now
produce absent keys, matching the memory, Drizzle and Postgres adapters.

If you relied on `role.inherits` always being an array, read it as
`role.inherits ?? []`.
