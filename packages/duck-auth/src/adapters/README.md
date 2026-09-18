# Adapter query shapes

What a store call costs on each adapter, what was collapsed to get there, and how the numbers were
taken. Re-run `bun run bench:adapters` before trusting any of this on a dialect you have changed.

## One read

`Identities.Store` answers one read — `find(by)`, named with `{ id }`, `{ email }` or
`{ providerId, providerSub }`. Every dialect builds the same statement: the identity left joined to its
logins, `deleted_at is null`, ordered by `added_at`. Only the condition differs, so there is one plan to
reason about per dialect rather than three.

The provider lookup joins the link table a second time under its own alias (`lookup_link`) instead of
matching in a subquery. Both forms flatten to one plan on pg; on sqlite the subquery materialises a list
and sorts it in a temp b-tree, so the alias is 1.7x there.

MySQL is the one with a second parameter — `find(by, hidden)`. It has no `RETURNING`, so `erase`,
`softDelete` and `restore` have to read back the row they just hid or removed, and that is the only read
allowed to see a hidden row.

## One statement

On Postgres `create` and `erase` are a single statement, not a transaction around two:

- `create` — the identity insert and the links insert are two arms of one `with`, and the links take the
  id out of the identity's own CTE (`select written.id from written`), so no id is minted in JS. A
  refused login takes the identity down with it, with no window and no transaction to hold open. With no
  logins to write there is no second arm, so it is a plain insert (drizzle refuses `.values([])`).
- `erase` — the links are read in the same `with` that deletes their owner. Every arm of a `with` sees
  the snapshot the statement opened on, so the cascade cannot outrun the read, and the row that comes
  back carries the logins that went with it.

Neither collapse ports: sqlite has no DML inside a `WITH`, and mysql has no `RETURNING`, so both keep
the transaction. Against the shape each replaced, interleaved so both meet the same machine load:
`create` 1.3–1.4x, `erase` 1.43x, four round trips down to one in each case.

## Fewer statements per call

What a call costs on a real database is mostly the number of statements it sends: each one is a round
trip the caller waits through. Four shapes sent more than they had to.

**`link` — the holder check is the insert.** It read the identity to see whether it was there, inserted
the login, then read the identity again to answer. The first read is gone: the insert takes its row from
`auth_identities` (`insert … select … where id = $1 and deleted_at is null`), so an identity that is gone
or hidden writes nothing and the read that answers returns `null` on its own. MySQL held a locked read
and a second read for "does this identity already hold this provider" on top, both inside a transaction;
the repeat is settled in the same `where` now, through the derived table MySQL requires of a query that
names its own insert target.

**`patchMetadata` — merge in the database.** It read the row, merged in JS, wrote against the version it
had read, and retried once when a concurrent write took that version first. It is one `update` now:
`metadata || $patch::jsonb` on pg, `json_set` on sqlite and MySQL. The merge happens under the row's own
lock, so there is no window to lose and nothing to retry.

`json_patch`/`json_merge_patch` would have been shorter still, and wrong: they are RFC 7396, where a null
value removes the key rather than storing it. `json_set` writes each key where it sits, which is what the
object spread the memory adapter runs does — checked key for key against it, a key with a dot in its name,
a nested object and a null value included.

**`merge` — the survivor is matched, not read.** Two reads told it what the survivor already held: the
credential kinds it could not accept a second of, and the providers whose logins would clash on the owned
index. Both are conditions on the writes that used them now — an `exists` over the survivor's own rows —
and the logins that clash stay where they are for the cascade under the final delete to take, rather than
being cleared by a statement of their own. MySQL reads both through a derived table, since it refuses a
subquery that names the statement's own target.

**MySQL's locked reads.** `update`, `softDelete`, `rotate`, `revoke` and `patchMetadata` each took a
`select … for update` to learn whether the row was there at the version expected, then did the write. The
write takes that same lock and `affectedRows` answers that same question, so the probe is gone from all
five, and `restore` no longer reads the row twice.

`erase` keeps its locked read. It has to answer with the row it removed, so the read comes before the
delete either way, and the lock is what stops two concurrent erases both claiming they took it.

## Numbers

`bun run bench:adapters`, 2026-09-17, M-series laptop, 50k identities and 100k logins on every backend.
One backend per run, each started once the one-minute load average was under 3, so a spike costs one table
rather than the set. p50 / p95 at the adapter boundary — drizzle building the SQL, the driver, the round
trip and the row mapping, because that is what a caller waits for.

p50 side by side, then each adapter with its p95 and what shapes it:

| call | Memory | SQLite | Postgres | MySQL |
| --- | --- | --- | --- | --- |
| `find({ id })` | 3 µs | 0.089 ms | 0.280 ms | 0.255 ms |
| `find({ email })` | 7 µs | 0.090 ms | 0.299 ms | 0.259 ms |
| `find({ providerId, providerSub })` | 8 µs | 0.112 ms | 0.383 ms | 0.282 ms |
| `create (2 logins)` | 2.125 ms | 0.632 ms | 0.650 ms | 1.184 ms |
| `erase` | 3 µs | 0.543 ms | 0.499 ms | 1.348 ms |
| `link` | 0.630 ms | 0.454 ms | 0.549 ms | 1.404 ms |
| `patchMetadata` | 4 µs | 0.282 ms | 0.271 ms | 0.906 ms |

### Memory

A `Map` read for the id, a scan for the rest. `create` is the outlier because it checks the address,
the handle and every login against every row it holds — 50k of them here. That is the adapter being a
test double, not a store to run 50k accounts through.

| call | p50 | p95 | before | statements |
| --- | --- | --- | --- | --- |
| `identities.find({ id })` | 3 µs | 5 µs | — | — |
| `identities.find({ email })` | 7 µs | 0.013 ms | — | — |
| `identities.find({ sub })` | 8 µs | 0.013 ms | — | — |
| `identities.create` | 2.125 ms | 2.646 ms | 2.264 ms | 3 scans -> 1 |
| `identities.update` | 6 µs | 10 µs | — | — |
| `identities.link` | 0.630 ms | 1.125 ms | — | — |
| `identities.unlink` | 6 µs | 0.011 ms | — | — |
| `identities.softDelete` | 6 µs | 9 µs | — | — |
| `identities.restore` | 5 µs | 8 µs | — | — |
| `identities.erase` | 3 µs | 6 µs | — | — |
| `credentials.create` | 4 µs | 8 µs | — | — |
| `credentials.findById` | 2 µs | 3 µs | — | — |
| `credentials.findByHashedSecret` | 0.046 ms | 0.057 ms | — | — |
| `credentials.findByProviderSub` | 6 µs | 10 µs | — | — |
| `credentials.listByIdentity` | 0.011 ms | 0.013 ms | — | — |
| `credentials.patchMetadata` | 4 µs | 5 µs | — | — |
| `credentials.rotate` | 4 µs | 6 µs | — | — |
| `credentials.revoke` | 4 µs | 6 µs | — | — |
| `credentials.delete` | 2 µs | 3 µs | — | — |
| `credentials.deleteByKind` | 0.011 ms | 0.014 ms | — | — |
| `sessions.create` | 4 µs | 8 µs | — | — |
| `sessions.getByHash` | 2 µs | 3 µs | — | — |
| `sessions.update` | 4 µs | 5 µs | — | — |
| `sessions.listByIdentity` | 0.012 ms | 0.015 ms | — | — |
| `sessions.delete` | 0 µs | 1 µs | — | — |

Controls — the calls above with no `before`; nothing in this pass touched them — came out 0.75x to 1.02x of the earlier run over the 24 with a measurable earlier sample, median 1.00x, widest `identities.erase` and `credentials.findByHashedSecret`. That spread is the machine, and the `before` column has to be read against it.

No changed call clears it: here the statement count is the claim and the milliseconds are not.

### SQLite (bun:sqlite, file)

In-process, so no round trip to pay; the writes are what a durable commit costs. better-sqlite3 measured
roughly 1.7x slower on the reads on the same machine.

| call | p50 | p95 | before | statements |
| --- | --- | --- | --- | --- |
| `identities.find({ id })` | 0.089 ms | 0.105 ms | — | — |
| `identities.find({ email })` | 0.090 ms | 0.127 ms | — | — |
| `identities.find({ sub })` | 0.112 ms | 0.174 ms | — | — |
| `identities.create` | 0.632 ms | 0.996 ms | — | — |
| `identities.update` | 0.332 ms | 0.482 ms | — | — |
| `identities.link` | 0.454 ms | 0.784 ms | 0.535 ms | 3 -> 2 |
| `identities.unlink` | 0.411 ms | 0.567 ms | — | — |
| `identities.softDelete` | 0.320 ms | 0.426 ms | — | — |
| `identities.restore` | 0.315 ms | 0.473 ms | — | — |
| `identities.erase` | 0.543 ms | 1.353 ms | — | — |
| `credentials.create` | 0.374 ms | 0.561 ms | — | — |
| `credentials.findById` | 0.066 ms | 0.074 ms | — | — |
| `credentials.findByHashedSecret` | 0.077 ms | 0.085 ms | — | — |
| `credentials.findByProviderSub` | 0.082 ms | 0.090 ms | — | — |
| `credentials.listByIdentity` | 0.073 ms | 0.080 ms | — | — |
| `credentials.patchMetadata` | 0.282 ms | 0.356 ms | 0.357 ms | 2 -> 1 |
| `credentials.rotate` | 0.354 ms | 0.422 ms | — | — |
| `credentials.revoke` | 0.283 ms | 0.357 ms | — | — |
| `credentials.delete` | 0.348 ms | 0.407 ms | — | — |
| `credentials.deleteByKind` | 0.392 ms | 0.556 ms | — | — |
| `sessions.create` | 0.418 ms | 0.586 ms | — | — |
| `sessions.getByHash` | 0.064 ms | 0.071 ms | — | — |
| `sessions.update` | 0.068 ms | 0.545 ms | — | — |
| `sessions.listByIdentity` | 0.063 ms | 0.077 ms | — | — |
| `sessions.delete` | 0.363 ms | 0.454 ms | — | — |
| `events.listByIdentity` | 0.059 ms | 0.065 ms | — | — |

Controls — the calls above with no `before`; nothing in this pass touched them — came out 0.83x to 1.10x of the earlier run over the 25 with a measurable earlier sample, median 1.00x, widest `credentials.rotate` and `identities.erase`. That spread is the machine, and the `before` column has to be read against it.

Clearing it: `credentials.patchMetadata` 0.79x. For the rest the statement count is the claim and the milliseconds are not.

### Postgres 18.4 (node-postgres, localhost)

Server-side, the reads are 0.035–0.049 ms over 10–14 shared buffer hits, every node an index scan. The
driver round trip is therefore ~5x the query, and a pooler or a co-located database is the only thing
left that moves a read here.

| `find(by)` | index driving it |
| --- | --- |
| `{ id }` | `auth_identities_pkey` |
| `{ email }` | `uq_auth_identities_email` on `lower(profile->>'email')` |
| `{ providerId, providerSub }` | `uq_auth_identity_providers_sub` → pkey → `auth_identity_providers_identity` |

| call | p50 | p95 | before | statements |
| --- | --- | --- | --- | --- |
| `identities.find({ id })` | 0.280 ms | 0.348 ms | — | — |
| `identities.find({ email })` | 0.299 ms | 0.349 ms | — | — |
| `identities.find({ sub })` | 0.383 ms | 0.444 ms | — | — |
| `identities.create` | 0.650 ms | 0.838 ms | — | — |
| `identities.update` | 0.548 ms | 0.643 ms | — | — |
| `identities.link` | 0.549 ms | 0.679 ms | 0.801 ms | 3 -> 2 |
| `identities.unlink` | 0.432 ms | 0.514 ms | — | — |
| `identities.softDelete` | 0.608 ms | 1.091 ms | — | — |
| `identities.restore` | 0.494 ms | 0.554 ms | — | — |
| `identities.erase` | 0.499 ms | 0.570 ms | — | — |
| `credentials.create` | 0.290 ms | 0.406 ms | — | — |
| `credentials.findById` | 0.218 ms | 0.236 ms | — | — |
| `credentials.findByHashedSecret` | 0.240 ms | 0.260 ms | — | — |
| `credentials.findByProviderSub` | 0.236 ms | 0.271 ms | — | — |
| `credentials.listByIdentity` | 0.249 ms | 0.283 ms | — | — |
| `credentials.patchMetadata` | 0.271 ms | 0.326 ms | 0.555 ms | 2 -> 1 |
| `credentials.rotate` | 0.283 ms | 0.323 ms | — | — |
| `credentials.revoke` | 0.255 ms | 0.280 ms | — | — |
| `credentials.delete` | 0.210 ms | 0.230 ms | — | — |
| `credentials.deleteByKind` | 0.228 ms | 0.279 ms | — | — |
| `sessions.create` | 0.235 ms | 0.274 ms | — | — |
| `sessions.getByHash` | 0.187 ms | 0.227 ms | — | — |
| `sessions.update` | 0.261 ms | 0.286 ms | — | — |
| `sessions.listByIdentity` | 0.243 ms | 0.266 ms | — | — |
| `sessions.delete` | 0.164 ms | 0.192 ms | — | — |
| `events.listByIdentity` | 0.211 ms | 0.231 ms | — | — |

Controls — the calls above with no `before`; nothing in this pass touched them — came out 0.61x to 1.18x of the earlier run over the 25 with a measurable earlier sample, median 0.98x, widest `identities.update` and `identities.softDelete`. That spread is the machine, and the `before` column has to be read against it.

Clearing it: `credentials.patchMetadata` 0.49x. For the rest the statement count is the claim and the milliseconds are not.

### MySQL 8 (mysql2, localhost)

Reads match pg. The writes carry the transaction and the read-back that no `RETURNING` forces, which is
also why there was the most here to take away.

| call | p50 | p95 | before | statements |
| --- | --- | --- | --- | --- |
| `identities.find({ id })` | 0.255 ms | 0.298 ms | — | — |
| `identities.find({ email })` | 0.259 ms | 0.329 ms | — | — |
| `identities.find({ sub })` | 0.282 ms | 0.322 ms | — | — |
| `identities.create` | 1.184 ms | 1.847 ms | — | — |
| `identities.update` | 1.121 ms | 1.912 ms | 1.324 ms | 5 -> 4 |
| `identities.link` | 1.404 ms | 3.690 ms | 1.554 ms | 6 -> 2 |
| `identities.unlink` | 1.210 ms | 2.118 ms | — | — |
| `identities.softDelete` | 1.308 ms | 2.207 ms | 1.524 ms | 5 -> 4 |
| `identities.restore` | 1.717 ms | 2.885 ms | 1.596 ms | 6 -> 5 |
| `identities.erase` | 1.348 ms | 2.158 ms | — | — |
| `credentials.create` | 1.022 ms | 2.060 ms | — | — |
| `credentials.findById` | 0.210 ms | 0.248 ms | — | — |
| `credentials.findByHashedSecret` | 0.221 ms | 0.250 ms | — | — |
| `credentials.findByProviderSub` | 0.227 ms | 0.258 ms | — | — |
| `credentials.listByIdentity` | 0.238 ms | 0.278 ms | — | — |
| `credentials.patchMetadata` | 0.906 ms | 1.844 ms | 1.305 ms | 6 -> 4 |
| `credentials.rotate` | 1.335 ms | 2.304 ms | 1.518 ms | 5 -> 4 |
| `credentials.revoke` | 1.410 ms | 2.393 ms | 1.607 ms | 5 -> 4 |
| `credentials.delete` | 1.311 ms | 2.233 ms | — | — |
| `credentials.deleteByKind` | 1.250 ms | 2.110 ms | — | — |
| `sessions.create` | 0.621 ms | 1.168 ms | — | — |
| `sessions.getByHash` | 0.211 ms | 0.261 ms | — | — |
| `sessions.update` | 0.673 ms | 1.124 ms | — | — |
| `sessions.listByIdentity` | 0.251 ms | 0.285 ms | — | — |
| `sessions.delete` | 0.499 ms | 1.423 ms | — | — |
| `events.listByIdentity` | 0.214 ms | 0.250 ms | — | — |

Controls — the calls above with no `before`; nothing in this pass touched them — came out 0.52x to 1.11x of the earlier run over the 20 with a measurable earlier sample, median 0.91x, widest `sessions.update` and `identities.unlink`. That spread is the machine, and the `before` column has to be read against it.

No changed call clears it: here the statement count is the claim and the milliseconds are not.

## How these were measured

`scripts/bench-adapters.ts`, one backend per process, same seed and same harness for all four:

- **Seed.** 50k identities, two logins each, addresses `user{n}@example.com` and subs `{provider}-{id}`,
  written in bulk SQL (a recursive CTE on sqlite and mysql, `generate_series` on pg) so the seed is not
  the store's own write path. Memory is filled through `raw`, because seeding 50k rows through its
  `create` is quadratic and would measure the seed.
- **Schema.** The same `src/test/*-e2e-schema.sql` the e2e suites apply, so the indexes are the shipped
  ones and not something a benchmark invented.
- **Containers.** `postgres:18.4-alpine3.24` and `mysql:8.4`, started and removed by the script, published
  on their own ports so nothing collides with the e2e run.
- **Timing.** 30 warm-up calls, then 300 timed reads and 200 timed writes; `performance.now()` around
  each awaited call, p50 and p95 off the sorted samples. Erases run over rows created up front, so the
  create is not inside the erase's clock.
- **Settling.** pg gets `vacuum analyze` + `checkpoint`, mysql `analyze table`, then both sit for 8s.
  Reads taken straight after a 150k-row seed measure the seed's dirty buffers, not the query. MySQL gets
  no `flush tables`: it drops the table cache InnoDB has just warmed and doubles every number after it.
- **Server-side cost** separately, through `explain (analyze, buffers)`, to separate the query from the
  driver round trip that carries it.
- **Before/after.** The tables carry a `before` column for every call whose shape changed, taken from a
  full run on the old code. Every other call in the same table is the control: nothing in that pass
  touched it, so how far those moved between the two runs is the noise the changed ones were read
  against, and it is quoted under each table. Where a collapse was small enough to sit inside that noise,
  the statement count is the claim and the milliseconds are not.
- **Statement counts** come from drizzle's own query logger, not from reading the code: every statement
  each call sends, transaction and all, counted on a fresh database.

Caveats worth keeping in mind. This is one laptop under variable load: absolute milliseconds move by 10x
when the machine is busy, which is why the before/after work is quoted as ratios. The four tables are
not an engine comparison either — different drivers, different durability defaults, different amounts of
in-process work — they are each adapter measured against itself.

## What the numbers caught

MySQL's `find({ email })` was **24 ms**, 50x every other read, because the where matched
`lower(profile ->> '$.email')` while the unique index lives on the `email_norm` column generated from
that expression. MySQL will not use a generated-column index when the comparison carries the
connection's collation (`utf8mb4_unicode_ci` from mysql2, against the column's `utf8mb4_0900_ai_ci`), so
`explain` showed `type: ALL`, 49,728 rows, `Using temporary; Using filesort`. Matching the stored column
instead makes it `type: const`, one row: **0.28 ms**. Nothing in the test suite could see this — every
assertion passed either way, on a table of ten rows.

The memory adapter's `create` reads every row it holds to check the address, the handle and each login.
Collapsing that from a pass per login plus one for the profile into a single scan moved it 2.264 ms to
2.125 ms — 6%, inside what the untouched calls moved between the two runs, because the passes were never
the cost. The comparisons are: two `toLowerCase` per row
per field, 50k times. Only an index would move it, and `raw` is a `Map` callers write to directly, so an
index kept beside it would be stale the moment a test seeded through it. It stays a scan.

## What is not worth doing

Reading an identity by provider sub touches `auth_identity_providers` twice — once through
`uq_auth_identity_providers_sub` to learn whose login it is, then through
`auth_identity_providers_identity` to list that identity's logins. They answer different questions, so
one touch means denormalising the logins onto the identity row, which drops the
`(provider_id, provider_sub)` unique that stops two accounts claiming one login. The second probe is a
range scan over a handful of rows. Leave it.

MySQL's `erase` keeps the `select … for update` the other writes lost. It has to answer with the row it
removed, so that read comes before the delete whatever else changes, and the lock is the only thing
stopping two concurrent erases from both reporting they took it.

`create` and `erase` stay a transaction on sqlite and MySQL. Postgres does each in one statement because
a data-modifying `with` can carry the write and the read that answers it; sqlite allows no DML inside a
`WITH` at all, and MySQL has no `RETURNING` to answer from. There is nothing to collapse into.
