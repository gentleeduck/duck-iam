---
'@gentleduck/auth': patch
---

Add `createdBy`/`updatedBy` columns to the drizzle adapter's tables (`authIdentities`,
`authCredentials`, `authSessions`, `authEvents`), matching the pattern
`@gentleduck/iam`'s drizzle schemas already use.

Nullable, and never set by the adapter itself (it has no actor context) - set them from
triggers or direct admin writes. `updatedBy` only exists on `authIdentities`, the only
table with an `updatedAt` column.
