---
'@gentleduck/auth': patch
---

Fix three defects in the drizzle bridges.

Postgres: two `@>` containment predicates ended in `]::jsonb`, a stray bracket that made
the SQL invalid, so `findByProvider` and provider linking failed outright rather than
returning nothing. Neither had a suite pointed at a real Postgres until now.

Postgres: `findById` on a `uuid` primary key raises `22P02 invalid_text_representation`
for a string that is not a UUID, so an id taken straight off a request produced a 500
carrying the SQL rather than a clean unauthenticated error. Every other adapter returns
null for an unknown id, and the store contract is "unknown id", not "crash". An
unrepresentable id is treated as absent.

MySQL: `json` columns come back already parsed, so the `Date` fields nested in `factors`
and `actingAs` arrived as ISO strings against a type that promises `Date`, and anything
calling `factor.completedAt.getTime()` threw on MySQL alone. Rows are revived on read,
the way the Postgres adapter and the Redis store already do.
