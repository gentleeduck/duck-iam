---
'@gentleduck/iam': minor
---

Harden and type the Drizzle adapter schemas (pg, mysql, sqlite).

- Add `json: 'native' | 'string'` adapter option. `'native'` (default) writes plain objects to `jsonb`/`json` columns so payloads stay queryable; `'string'` JSON-stringifies for SQLite/text columns. The read path accepts both, so switching is migration-safe.
- Type every JSON column with `$type<>()` against the `AccessControl` types; constrain `algorithm` with a Postgres enum, a MySQL enum, and a SQLite CHECK.
- Add CHECK constraints (non-blank name/subject, `version >= 1`), `created_by` / `updated_by` audit columns, GIN indexes (pg), partial indexes for scoped rows (pg/sqlite), and a `roleId` index.
- Collapse NULL scopes in unique constraints (`NULLS NOT DISTINCT` on pg, `COALESCE(scope, '')` on mysql/sqlite) so duplicate global rows are rejected.
- Name every constraint (`pk_`, `fk_`, `uq_`, `idx_`, `ch_`).

Fixes: pg `inherits` was `text[]` but the shared adapter writes JSON, so it is now `jsonb`; the MySQL timestamp default was a static import-time snapshot and is now per-row `CURRENT_TIMESTAMP(3)`.

Migration note: regenerate migrations with `drizzle-kit generate`. SQLite users must pass `json: 'string'`.
