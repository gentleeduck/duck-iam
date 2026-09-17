---
'@gentleduck/auth': minor
---

Storage adapters: one class per backend, implementing the engine's store
contracts directly, plus a `.wrap()` escape hatch on every adapter call.

### The bridge layer is gone

`@gentleduck/auth/adapters/sql` used to define a second, lower-level contract —
23 operations shaped around a `where`/`patch` pair — that each dialect
implemented and `sqlStores` then translated into the four stores the engine
actually binds. Two contracts for one job: every method was written twice, and
the translation layer was where the miss-is-`null` rule, the actor stamping and
the `patchMetadata` retry lived, invisible to the dialect that produced the row.

Each adapter now implements `Identities.Store`, `Credential.Store`,
`Sessions.Store` and `Events.Store` itself. What the translation layer held is
either inlined where it belongs or shared as a free helper on the new base.

Removed from `@gentleduck/auth/adapters/sql`: `SqlBridge`, `SqlStore`,
`SqlStores`, `sqlStores`, `SqlIdentityStore`, `SqlCredentialStore`,
`SqlSessionStore`, `SqlEventStore`, `asBridge`, `orNull`. The entry point keeps
`withSqlEventLog` and the JSON-column codecs, which were never part of it, and
is now `@gentleduck/auth/adapters/drizzle`: with the bridge gone there is no
dialect-agnostic SQL contract left for the old name to describe, and everything
behind it is shared only by the three drizzle dialects.

Renamed, with the two statics collapsed into one:

| before | after |
| --- | --- |
| `DrizzlePgBridge.bridge(db)` / `.storage(url)` | `new DrizzlePgAdapter(db \| url \| pool)` |
| `DrizzleMysqlBridge.bridge(db)` / `.storage(url)` | `new DrizzleMysqlAdapter(db \| url \| pool)` |
| `DrizzleSqliteBridge.bridge(db)` / `.storage(path)` | `new DrizzleSqliteAdapter(db \| path \| client)` |
| `createSqlStores(bridge)` | — (an adapter is already the stores) |

There is no `open()` static: the constructor takes the connection string, the
driver pool or a drizzle handle and resolves it, so `new` is the only way in.

`MemoryIdentityStore`, `MemorySessionStore`, `MemoryCredentialStore` and
`MemoryOrgStore` are no longer exported separately: `MemoryAdapter` is one class
on the same base, with the same four facets. `memoryAdapter()`, `memoryStorage()`
and `MemoryAdapter#raw` are unchanged.

### One base class, one contract

`@gentleduck/auth`'s adapter layer is now two declarations. `Adapter` is the
contract and nothing else: the four stores, the `Answer<T>` a call returns and
the `Result<T>` its `wrap()` hands back. `AdapterStore` is the class every
adapter extends: it takes its driver's error mapper and exposes `run`, the one
place a failure is typed and `wrap` is attached.

`asAdapter` is gone. It checked at runtime that an adapter had all four stores —
something `implements Adapter.Me` already proves at compile time — and used that
check to launder the profile type. `DrizzlePgBridge.storage<MyProfile>(db)` is now
`new DrizzlePgAdapter(db)`: an adapter answers the profile shape its table
actually declares, so an app whose profile is narrower than that is told so by
the compiler rather than trusted at runtime.

`answering(promise)` is now `AdapterStore.answer(promise)`, and `LOG_PAGE`,
`stamped` and `rowWithLinks` moved to `@gentleduck/auth/adapters/drizzle`, next to
the schemas that use them.

### A store is plain CRUD

`Identities.Store` declared six optional set-based writes alongside the
single-row ones — `softDeleteMany`, `restoreMany`, `eraseMany`,
`updateProfileMany`, `linkMany`, `unlinkMany` — as a fast path a store could
implement instead of being looped over. No adapter ever did, in any dialect, so
every one of them was a branch that never ran and a compliance test that only
ever skipped. They are gone, and the contract is the single-row CRUD it always
was in practice.

`AuthIdentities#softDeleteMany` and its five siblings are unchanged: the facet
loops, reports one outcome per input row in input order, and names each refusal
the same way it did before.

### `.wrap()` — a failure as a value

Every adapter call now answers an `Adapter.Answer<T>`, a native promise with one
extra method:

```typescript
const { data, error } = await storage.identities.find({ email }).wrap()
if (error) return reply(error.code)
```

`error` is the discriminant and is always an `AuthError`, never `unknown`: a
non-`Error` a driver throws becomes the `cause` of a real one rather than being
handed back raw. `Answer<T>` extends `Promise<T>`, so awaiting it throws exactly
as before and every existing caller — `Promise.all` included — is untouched.

Scope: `wrap()` catches what the call rejects with. An argument that throws
before there is a promise still throws at the call site; a bug in the call is not
a failure of the work.

`error` also carries the codes that call can raise, not a flat `AuthError`:

```typescript
const { error } = await storage.sessions.update(id, patch).wrap()
//    ^? AuthError<'AUTH_SESSION_REVOKED' | Adapter.Faults> | null
```

`Adapter.Faults` is what any call can raise — the whole range of a driver's
error mapper, since any statement can meet a constraint, a dead socket or a
missing schema. `Adapter.Me` names what each method adds on top: `restore` can
answer `AUTH_GRACE_EXPIRED`, `patchMetadata` and `upsert`
`AUTH_CREDENTIAL_NOT_FOUND`, `update` `AUTH_SESSION_REVOKED`. The union is
closed, so a `switch` on `error.code` is exhaustive, and comparing a read's
error against a code it cannot raise no longer compiles.

`AdapterStore.answer(promise)` now types the failure on the await path too, as
`run` always did, and attaches `wrap` to a promise of its own rather than to the
caller's.

Each adapter declares its facets as their slot in `Adapter.Me` rather than
checking an inferred object against the contract with `satisfies`. A `satisfies`
only proves the body is assignable, so the type a caller saw came from the body —
`run`'s `Adapter.Faults` and nothing else — and the extra codes above were
declared where no call site could read them. `storage.identities.restore(id)`
now answers `AuthError<'AUTH_GRACE_EXPIRED' | Adapter.Faults>`, which is what
this section always said it did.

### Fixes this turned up

- `merge` re-pointed the duplicate's credentials, sessions and logins and only
  then discovered the survivor was gone, leaving the duplicate destroyed for
  nothing. Both sides are confirmed before anything moves, on all three dialects.
- `link` against an identity that no longer exists surfaced the foreign-key
  violation as `AUTH_IDENTITY_NOT_FOUND`; it now answers `null`, as every other
  read of a missing row does.
- A soft delete no longer takes `deletedAt`/`deletedBy` from the caller: the
  window is a grace period in milliseconds and the actor is the ambient one, so
  two dialects can no longer disagree about when a row becomes purgeable.
- An empty session patch is a no-op rather than a driver syntax error, and a
  missing session answers `AUTH_SESSION_REVOKED` on every backend.
- `patchMetadata` on a row that is not there (or not this tenant's) answers
  `AUTH_CREDENTIAL_NOT_FOUND` rather than telling the caller to retry.

### One read per adapter, and no handle to pass

Each dialect had a private read taking the client to read through, so all ten of
its call sites passed `this._db` to say "the usual one". The read now uses the
adapter's own handle, and a transaction binds an adapter to its `tx` —
`this.withClient(tx)` — so nothing is threaded anywhere and no call site can
quietly read outside the transaction it is in.

MySQL had three row helpers where the others had one: a locked re-read, a links
read and an assembler over both. It now answers every lookup through the same
single join the other two dialects use, leaving one helper — the lock a write
takes before it re-reads.

On Postgres, `create` and `erase` are one statement each rather than a
transaction around two. The row, its logins and the read that answers them
travel as one CTE, with the links taking the id straight out of it; `erase`
reads the logins in the same `with` that deletes their owner, since every arm
of one sees the snapshot the statement opened on. Four round trips become one,
and the row an erase answers with now carries the logins the cascade took —
proven for every adapter, not just this one.

### One `withClient`, on the adapter

A transaction was joined store by store: every store contract carried its own
optional `withClient`, each dialect implemented four one-line delegates back to
the adapter's own, and `withTransaction` called them one at a time. The facets
come off one adapter and share its connection, so that was four answers to one
question.

`withClient` belongs to the adapter now — `Adapter.Me` declares it, the three
drizzle adapters already had it, and `withTransaction` makes the one call. The
capability hook follows: `MfaFacet` and `ApiKeysFacet` are handed the bound
facets instead of a driver handle to rebind a store of their own from, so
`Capability.withClient(stores, events)` replaces `(client, events)` and neither
can answer `null` any more.

Hand the engine the adapter — `stores: adapter` — and transactions work. A bag
assembled facet by facet (redis sessions beside a drizzle identities store, say)
has no `withClient`, and `withTransaction` throws `AUTH_MISCONFIGURED` saying so
rather than leaving a write outside the caller's transaction. `createTest` takes
the same shape: one `stores` override in place of four per-facet ones.

### Fewer statements per call

What a store call costs on a real database is mostly the number of statements it
sends: each one is a round trip the caller waits through. Four shapes sent more
than they had to, on every dialect that had them.

`link` read the identity to check it was there, inserted the login, then read the
identity again to answer. The first read is gone — the insert takes its row from
`auth_identities`, so an identity that is gone or hidden writes nothing and the
read that answers returns `null` on its own. MySQL also held a locked read and a
second read for "does this identity already hold this provider", both inside a
transaction; the repeat is settled in the same `where` now. Three statements to
two on Postgres and SQLite, six to two on MySQL, and linking to a soft-deleted
identity no longer writes a row on MySQL that the answer then hides.

`patchMetadata` read the row, merged in JS, wrote against the version it had read
and retried once when a concurrent write took that version first. It is one
`update` now — `metadata || $patch::jsonb` on Postgres, `json_set` on SQLite and
MySQL — so the merge happens under the row's own lock and there is no window to
lose. Not `json_patch`/`json_merge_patch`: those are RFC 7396, where a null value
removes the key rather than storing it, which is not what the object spread the
memory adapter runs does.

`merge` read the survivor's credential kinds and provider ids to decide what the
duplicate could keep. Both reads are now conditions on the writes that used them,
and the logins that clash stay where they are for the cascade under the final
delete to take, rather than being cleared by a statement of their own.

MySQL took a `select … for update` before `update`, `softDelete`, `rotate`,
`revoke` and `patchMetadata` to learn whether the row was there at the version
expected. The write takes the same lock and `affectedRows` answers the same
question, so the probe is gone from all five, and `restore` no longer reads the
row twice. `erase` keeps its locked read: it has to answer with the row it
removed, so that read comes before the delete either way.

The memory adapter's `create` checked the address, the handle and each login in a
pass of its own; it is one scan now, which is also the one place the three unique
indexes every dialect carries are written down together.

One fix fell out of it: `patchMetadata` could raise `AUTH_STALE_WRITE` after
losing the version twice, a code its own fault union does not name and a retry
its caller could not act on. There is no version to lose now, so the only failure
left is the `AUTH_CREDENTIAL_NOT_FOUND` the contract declares.

`bun run bench:adapters` times all 26 store calls on all four adapters. The
before and after tables, per call, are in `src/adapters/README.md`.

An identity store answers one read. `findById`, `findByEmail` and
`findByProviderSub` are `find(by)`, named with `{ id }`, `{ email }` or
`{ providerId, providerSub }` — three names for one join, one live filter and
one order, where only the condition ever differed. `auth.identities.getById`
and its siblings are unchanged; it is stores that change shape, so
`stores.identities.findById(id)` is now `stores.identities.find({ id })`.

The `where` clauses that scope a read to a tenant were each a mutable array and
a pair of `if`s; they are one `and(...)` with a shared `inTenant` filter that
drops out when the caller named no tenant.

MySQL read an identity by address 50x slower than by any other key. The
`where` matched `lower(profile ->> '$.email')` while the unique index lives on
the `email_norm` column generated from that expression, and MySQL will not use
a generated-column index when the comparison carries the connection's
collation - so every lookup scanned the table. It matches the stored column
now: 24 ms to 0.28 ms over 50k rows. No test could see it, since every
assertion passed either way on a table of ten rows.

`bun run bench:adapters` is what found it: the same 50k identities and 100k
logins on all four adapters, timed at the adapter boundary. The numbers, the
plans behind them and the method are in `src/adapters/README.md`.

### One way a driver failure is named

Each dialect had its own translator: the same five makers, the same socket-code
list and its own four-deep cause-chain walker, restated three times, with a
`Make` that took one argument in two of them and two in the third.

There is now one reader — `signalOf` — and one resolver, and each dialect is
only its own table of what its driver says: the text it names the refused index
in, the code or errno it gives, the family that code belongs to, read in that
order. 256 lines became 189, and nothing an adapter answers changed.

`AuthError` itself no longer declares each code's HTTP status twice — once as a
literal on the union member and once in the status table that is the only one
ever read — and the class is free of type assertions: the origin argument is
narrowed by a predicate, and `toJSON` scrubs through a function that returns a
record rather than one that is cast to it.
