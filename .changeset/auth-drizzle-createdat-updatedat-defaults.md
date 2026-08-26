---
'@gentleduck/auth': patch
---

Add DB-level defaults for `createdAt`/`updatedAt` on the drizzle adapter's tables
(`authIdentities`, `authCredentials`, `authSessions`, `authEvents`), matching the
pattern `@gentleduck/iam`'s drizzle schemas already use.

The store layer already sets both fields explicitly on every insert and update, so this
changes no observable behavior through the adapter's own API. It backstops rows written
outside that path (raw SQL, migrations, manual seeds) so `created_at` is never left null.
