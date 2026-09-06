---
'@gentleduck/auth': major
---

Provenance: audit columns that the API could not fill are now filled, and the ones that could only ever repeat another column are gone.

`auth_identities`, `auth_credentials` and `auth_sessions` have declared `created_by` and `updated_by` since 5.x. Nothing in the package wrote them and they were not on the row types, so every row in every deployment carried NULL provenance — the schema promised an audit trail the API could not produce.

**The ambient actor context** (mirrors the existing tenant one):

```ts
import { withActor } from '@gentleduck/auth'

await withActor(req.user.id, () => auth.identities.update(id, patch, version))
```

- `withActor(actorId, fn)` binds an actor across awaits. `withActor(undefined, fn)` clears the scope, the same fence `withTenant` provides.
- `resolveActor` on `AuthEngine` config is the process-wide fallback for hosts that already have a request context, so provenance does not depend on remembering to wrap every call. Also settable directly via `setDefaultActorResolver`.
- Precedence is explicit → ambient → configured default → `null`. Nothing bound records `null`, which is true; no `'system'` placeholder is invented.
- `identities.erase(id, { reason, operatorId })` used to accept `operatorId` and do `void opts`. It now binds it — and only when present, so an omitted one leaves an outer scope intact.

**Which tables carry what, and why:**

- `auth_identities` — `created_by`, `updated_by`, and a **new `deleted_by`**. "Who deleted this account" is the audit question that actually gets asked, and `deleted_at` alone could not answer it. Set with the delete marker, cleared by `restore`, so the pair never disagrees.
- `auth_credentials` — `created_by`, `updated_by`. Distinguishes a self-service password reset from an admin one.
- `auth_sessions` — **both columns dropped.** A session's author is its `identity_id`, and the one case where the operator differs is impersonation, which `acting_as` already models. A column that can only repeat another column drifts from it.
- `auth_events` — **new `actor_id`.** `identity_id` is the subject; this is the operator. Without it "admin X revoked user Y's session" was indistinguishable from "user Y revoked their own" — the one thing an audit log exists to record. `Events.Envelope` gained a matching `actorId`, stamped onto every audited event.

**Uniqueness is now a database guarantee on every dialect, and a typed error everywhere:**

- MySQL had none. It cannot index a JSON path directly, so email and username uniqueness was left to an application-layer check while pg and sqlite had real partial indexes. That is not a weaker guarantee, it is no guarantee — the check is read-then-write, so two concurrent signups both saw a free address and both got it. `auth_identities` now carries two generated `STORED` columns, `email_norm` and `username_norm`, that are NULL while a row is soft-deleted; MySQL permits any number of NULLs in a unique index, so this reproduces pg's and sqlite's `WHERE deleted_at IS NULL` partial indexes exactly. MySQL also gained the `chk_auth_identities_profile_shape` check the other two have had since 5.x.
- sqlite's unique indexes were **declared in a form drizzle-kit could not emit**. The index expression `json_extract(profile, '$.email')` contains a comma, which the generator splits on to find column names, so it produced DDL naming two nonexistent columns — anyone running `drizzle-kit push`/`generate` against the sqlite schema got no unique index at all. Both indexes now use `->>`, which SQLite has had since 3.38 and which mirrors what pg already did. The dialect's own email lookups were switched to the same expression so they can still use the index.
- A violation of either index now arrives as `AUTH_EMAIL_TAKEN` or the new `AUTH_USERNAME_TAKEN`, on every dialect, instead of a raw driver error. The pre-checks in the store are read-then-write and so are racy by construction; the index is what actually decides, and its answer used to surface as a 500 while the pre-check's surfaced as a 409. The driver error stays reachable on `cause`.
- The memory adapter enforced email on `create` and `restore`, username nowhere, and neither on `update` — so moving an identity onto another live row's email succeeded there and failed on every SQL dialect. All three paths now check both, and the rule moved into the shared store-compliance matrix so no adapter can drift from it again.

**Also fixed here:**

- `restore` and `restoreMany` no longer resurrect a provider login someone else claimed while the row was hidden. `findByProviderSub` skips soft-deleted rows, so the sub was genuinely free to take — and restoring past that left two live rows answering to one Google account, with lookups returning whichever the query plan ordered first. Now refused with `AUTH_PROVIDER_TAKEN` (batch reason `provider-taken`), mirroring the existing email guard. In the batch path the two clashes are checked before either is committed, so a row refused for its address does not go on to reserve its provider subs against later rows in the same call.
- `restoreMany` now reports *which* rule refused each row instead of guessing. It previously labelled every refusal `email-taken`, because that was the only clash there was; a provider clash would have arrived under the wrong reason.
- `duck-auth migrate` emitted DDL that had drifted from the declared schema: `email_verified`, `created_by`, `updated_by` and both `updated_at` columns were missing, so a database built from the CLI could not satisfy the adapter's own writes.
- `duck-auth migrate` did not emit `auth_events` **at all** — the audit log, the one table this release is about, was left for consumers to hand-write. It is now emitted, indexes included.
- The CLI emitted an `auth_identities.tenant_id` that no query in any dialect reads or writes. It was declared in the MySQL schema too, and indexed there. Dropped from both: it was a column that existed, filled itself with NULL forever, and read as data — the same defect this release removes from `auth_sessions`.
- The drift test that was supposed to catch all of this checked one direction over three tables. It now checks both directions over four: a column the schema declares and the CLI omits breaks writes outright, and a column the CLI emits that nothing declares is the quiet one that becomes permanent NULL.
- The sqlite adapter tests built their tables from DDL hand-written inside the test files — no foreign keys, no unique indexes, no checks, plus the same phantom `tenant_id`. The suite was passing against a schema no deployment has: session ids that violate `chk_auth_sessions_id_length`, credentials pointing at identities that do not exist. Both files now build from the generated schema (`bun run e2e:schema`), and 33 cases that only passed because the constraints were absent were fixed to use real ids and seed their foreign keys.

**Breaking:**

- `Identities.Me` and `Credential.Me` gain required `createdBy`/`updatedBy`; `Identities.Me` also gains required `deletedBy`. `Sessions.Me` loses `createdBy`/`updatedBy` and `Sessions.CreateInput` no longer omits them. Code that builds these rows by hand — fixtures, custom stores — must follow; code that only reads them is unaffected.
- `SqlBridge` custom implementations: `softDelete` and `softDeleteManyReturningIds` take a trailing `deletedBy`; `restore` must clear `deleted_by`; `updateProfileManyReturning` receives `updatedBy` in the patch. A bridge passing the patch through needs no change; one naming columns by hand, as the Postgres dialect does, must add them.
- `SqlBridge.restoreManyReturning` may now return `refused: { id, reason }[]` alongside `candidates` and `restored`. It is optional so an existing bridge still compiles, but a bridge that guards provider subs and does not report them will have those refusals reported as `email-taken` — only the dialect ran both clash queries, so only the dialect can say.
- New error codes `AUTH_PROVIDER_TAKEN` (409) and `AUTH_USERNAME_TAKEN` (409), and new batch failure reasons `provider-taken` and `username-taken`. Exhaustive switches over either will not compile until extended.
- Writes that used to fail with a raw driver error on a duplicate email or username now throw `AuthError`. Code matching on the driver's message or error number will no longer match; match on `code` instead, or read `cause`.
- MySQL only: `auth_identities` gains two generated columns. They are index carriers, not part of the row contract — a bare `SELECT *` on that table now returns them, and the adapter excludes them from its own selects. A custom query that spreads the row into an `Identities.Me` should do the same.

**Migration.** `created_by`/`updated_by` on identities and credentials already exist. New: `auth_identities.deleted_by`, `auth_events.actor_id`. Droppable: `auth_sessions.created_by`, `auth_sessions.updated_by`. Rows written before this release keep their NULL provenance.

```sql
ALTER TABLE auth_identities ADD COLUMN deleted_by text;
ALTER TABLE auth_events     ADD COLUMN actor_id   text;
ALTER TABLE auth_sessions   DROP COLUMN created_by, DROP COLUMN updated_by;
ALTER TABLE auth_identities DROP COLUMN tenant_id;  -- never read or written

-- "Everything operator X did", on an append-only table that only grows.
CREATE INDEX auth_events_actor_created ON auth_events (actor_id, created_at);
```

MySQL additionally needs the uniqueness that dialect never had. Resolve any
existing duplicates among live rows first — the index build fails otherwise, and
that failure is the pre-existing duplicates being reported, not a migration bug:

```sql
ALTER TABLE auth_identities
  ADD COLUMN email_norm VARCHAR(320)
    GENERATED ALWAYS AS (if(deleted_at is null, lower(profile ->> '$.email'), null)) STORED,
  ADD COLUMN username_norm VARCHAR(191)
    GENERATED ALWAYS AS (if(deleted_at is null, lower(profile ->> '$.username'), null)) STORED,
  ADD CONSTRAINT uq_auth_identities_email UNIQUE (email_norm),
  ADD CONSTRAINT uq_auth_identities_username UNIQUE (username_norm);
```

sqlite databases built from a previous `drizzle-kit` run have no unique indexes
at all — the generator could not emit them. Deduplicate live rows, then:

```sql
CREATE UNIQUE INDEX uq_auth_identities_email
  ON auth_identities ((lower(profile ->> '$.email'))) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_auth_identities_username
  ON auth_identities ((lower(profile ->> '$.username'))) WHERE deleted_at IS NULL;
```
