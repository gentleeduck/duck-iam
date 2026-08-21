---
'@gentleduck/auth': major
---

Make OIDC authorization codes and refresh tokens single-use under concurrency.

Both consumers read the row with a plain SELECT and then wrote. Under REPEATABLE READ a
SELECT is a snapshot read, so every concurrent transaction saw the row and, with nothing
checking the write, every one of them returned it. An authorization code was redeemable
as many times as it was presented at once, and two racers could both pass a refresh
token's rotation-reuse detection, which is the mechanism that is supposed to catch a
stolen token being replayed.

The write decides the winner now. `consumeCode` requires its DELETE to report exactly one
affected row; `consumeRefresh` adds `consumed_at IS NULL` to the UPDATE and requires the
same. A single `affectedRows` helper reads the count, since drizzle types a mutation
result on a loosely-typed `MySqlDatabase` as `unknown` and these counts are precisely
what make the operations single-use.

The consents index was declared non-unique, which broke the same operation two ways:
`upsert` relies on ON DUPLICATE KEY (MySQL) and ON CONFLICT (Postgres), and neither fires
without a unique key. On MySQL it appended a second consent row for the same
(identity_id, client_id) instead of replacing the scope, leaving `find` to return
whichever it reached first. On Postgres it raised 42P10 outright, so consent upsert did
not work at all.

BREAKING: `oidc_consents_id_client` becomes a unique index on both dialects. Deduplicate
existing rows per (identity_id, client_id), keeping the most recent `granted_at`, before
applying the migration, or the index will refuse to build.
