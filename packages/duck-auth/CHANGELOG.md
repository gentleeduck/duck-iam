# Changelog

## 5.8.0

### Minor Changes

- Add an optional post-authentication hook to the NestJS `nestSignIn` handler.

  `nestSignIn` was sealed: it ran CSRF, body parsing, the sign-in flow and intent execution
  with no seam between authenticating and responding, and `forward`/`executeIntents` are
  module-private. An app that had to refuse a sign-in on something the engine cannot know —
  a host allow-list, a suspended tenant, a per-identity block — had no way to do it without
  reimplementing the whole handler.

  ```ts
  nestSignIn(auth, {
    onAuthenticated: (outcome, req) =>
      outcome.session?.identityId
        ? denialFor(outcome.session.identityId)
        : undefined,
  });
  ```

  The hook runs after the credentials verify and the session row exists, before any intent
  reaches the response. Returning a `NestSignInDenial` revokes the session that was just
  created and answers with the error instead, so the client never receives the SID.

  Revoking is the library's job and not the caller's, deliberately: `nestSignIn` owns the sid,
  and a consumer who forgot the revoke would leave a live session sitting behind a 403 — a
  silent auth bypass. For the same reason a hook that _throws_ also revokes, and a denial the
  adapter cannot read (a blank code, or a 2xx status that would render the refusal as a
  success) still denies, at 403.

  Gating here rather than in front of `signIn` also means a caller has to prove the password
  before it learns anything, so a denial is not an enumeration oracle.

  `nestSignIn(auth)` is unchanged — the options argument is optional and every existing call
  site keeps its current behaviour. Adds the `NestSignInDenial` and `NestSignInOptions` types
  to `@gentleduck/auth/server/nestjs`.

## 5.7.1

### Patch Changes

- Export `StoredProviderLink` and `StoredFactor` from the drizzle entrypoints, so a
  consumer can name the types the tables now infer.

  5.7.0 moved the JSON columns onto `customType`, which put those two names into
  `authIdentities.$inferSelect` and `authSessions.$inferSelect`. They were only
  reachable through an internal bundle chunk, so anything that infers a type from a
  table rather than annotating it — a repository base class, a generic wrapper,
  `getTableColumns` — failed to compile:

  ```
  TS2883: The inferred type of 'AuthIdentitiesRepository' cannot be named without a
  reference to '.../dist/index-CRY_TusL.cjs'. This is likely not portable.
  A type annotation is necessary.
  ```

  Both types are now re-exported from `@gentleduck/auth/adapters/drizzle/pg`, `/mysql`
  and `/sqlite` alongside the tables they describe, which is the module a consumer
  already imports. They remain available from `@gentleduck/auth/adapters/sql` too.

  Types only — no runtime change, and nothing to migrate.

## 5.7.0

### Minor Changes

- Framework adapters now bind the request's actor scope, so writes carry provenance.

  `withActor`, `runWithAuditEnvelope` and `setDefaultActorResolver` all existed,
  and `events.audit.ts` documented the intended adapter wrap in its own docblock —
  but no adapter shipped it. A grep for `withActor` across `src/server/` returned
  nothing, so `created_by` / `updated_by` / `deleted_by` and
  `Events.Envelope.actorId` were `null` on every write a request drove, whether or
  not the request was authenticated.

  New, one per adapter:

  - middleware, for frameworks that compose a `next` — `expressActorContext(auth)`,
    `koaActorContext(auth)`, `honoActorContext(auth)`, `nestActorContext(auth)`
  - handler wrappers, for those that do not — `nextWithActor(auth, handler)`,
    `fastifyWithActor(auth, handler)`, `elysiaWithActor(auth, handler)`
  - `withGrpc` binds internally; it already had the resolved session in hand

  The primitives are exported from `@gentleduck/auth` for anything hand-rolled:
  `withRequestActor(auth, req, fn)`, `withResolvedActor(session, fn)` and
  `actorForSession(session)`.

  While impersonating, the actor is the operator behind `actingAs`, not the account
  being acted on: the subject is already the row being written, and the column
  exists to name the human accountable. That id reached audit _events_ through
  `auditEnvelopeFor` and never reached the provenance columns.

  An anonymous request, and one whose session will not resolve, both run unbound —
  a stale cookie on a public route must not become a 500, and refusing it is a
  guard's job. Both leave the actor `null`, which stays distinct from "the user did
  this themselves". `nestActorContext` reuses the session `makeGuard` resolved, so
  the pair costs one `resolveSession` rather than two.

- Adapters can now check the request fingerprint, not just stamp it at sign-in.

  `hijack.evaluate` and `resolveSession`'s `requestSnapshot` both existed, and the hijack policy
  (`onIpChange`, `onUserAgentChange`) could be configured, but no adapter read an IP or a
  User-Agent on the resolve path - so the pair recorded on the session was written at sign-in and
  never looked at again. The policy had no effect and the anomaly detectors never ran.

  Following the shape `duck-iam` uses for its request environment, each actor-context wrapper now
  takes an optional `getCaller`, and each adapter exports the reader to pass it:

  ```ts
  import {
    expressActorContext,
    expressCaller,
  } from "@gentleduck/auth/server/express";

  app.use(expressActorContext(auth, { getCaller: expressCaller }));
  ```

  - `expressCaller`, `koaCaller`, `fastifyCaller`, `nestCaller`, `elysiaCaller`, `honoCaller`,
    `nextCaller` read what the framework resolved and never a forwarded header - the host is the
    only layer that knows how many proxies it trusts. `nextCaller` reports the User-Agent only, as
    a Web `Request` carries no resolved peer address.
  - Supplying `getCaller` forwards an `Anomaly.RequestSnapshot` to `resolveSession` and compares
    the fingerprint with `hijack.evaluate`, which emits `suspicious` on any drift even when the
    configured reaction is `'ignore'`.
  - `onHijack` handles drift instead of the configured reaction, and is where `'rotate'` belongs:
    rotating writes a new session cookie onto the response, which a wrapper that only owns handler
    execution cannot do. Without it, `'mfa'` and `'revoke'` throw and `'rotate'` is audit-only.

  This is opt-in. Omit `getCaller` and the wrappers stay what they were - an attribution scope that
  refuses nothing - because switching it on starts acting on IP and User-Agent drift for sessions
  that were already issued.

  Two fixes fall out of the same work:

  - `callerContext` now truncates to the lengths `SessionsImpl.create` actually stores (exported as
    `SESSION_COLUMN_CAPS`: 64 for `ip`, 512 for `userAgent`, 256 for `fingerprint`). Normalising to
    a different length than the row would make a client with a long User-Agent compare unequal to
    its own stored value on every request - a permanent step-up loop.
  - The Nest adapter's private `callerOf` is folded into `nestCaller`, so its sign-in route
    normalises its fingerprint the same way every other adapter does.

- **Breaking, in a minor.** Drizzle tables now hand back the types they declare for
  their JSON columns. `$inferSelect` on `authIdentities` and `authSessions` changes
  shape, and the runtime values change with it, so anything reading these tables
  directly needs a look before upgrading — the version number will not warn you, this
  note is the warning.

  `authIdentities.providers`, `authSessions.factors` and `authSessions.actingAs`
  carried `.$type<T>()` annotations naming `Date` — a compile-time assertion and
  nothing else. What the driver actually returned was the ISO string
  `JSON.stringify` had written, so a direct `db.select().from(authIdentities)` —
  a supported read, since the tables are a public export — gave
  `providers[0].addedAt.getTime is not a function`, and `addedAt < new Date()`
  was quietly always `false`. Revival existed, but only inside `createSqlStores`,
  which a direct table select never reaches.

  Each of the three columns is now a `customType` whose `fromDriver` does the
  parsing. The SQL type is unchanged (`jsonb` / `json` / `text`), so this is not
  a migration. Unreadable values fail closed rather than becoming an
  `Invalid Date`: `addedAt` and `completedAt` read as `null` at the column and
  fall back to the row's own `createdAt` in the store, which is the layer that
  can see it; an `actingAs` whose window cannot be read is dropped.

  Two latent bugs surfaced with the types: the mysql bridge's `listByIdentities`
  and every sqlite session read returned rows without reviving them at all, and
  the pg and mysql bridges revived dates with `new Date(value as string)`, which
  turns corrupt input into an `Invalid Date` that satisfies `instanceof Date` and
  compares `false` against everything.

  ## What breaks, and how to migrate

  `typeof authIdentities.$inferSelect` used to say `providers: ProviderLink[]` with
  `addedAt: Date` while the value was a string. It now says `StoredProviderLink[]`
  with `addedAt: Date | null`, and the value matches. `authSessions.factors` moves
  the same way (`StoredFactor`, `completedAt: Date | null`), and `actingAs` is now
  `Sessions.ActingAs | null`.

  Two shapes to look for:

  - **A workaround that re-typed the column as a string.** The honest thing to write
    against the old behaviour was
    `Omit<typeof authIdentities.$inferSelect, 'providers'> & { providers: { addedAt: string, ... }[] }`.
    That is now wrong in the other direction, and because it is an `Omit` and replace
    rather than a narrowing it **keeps compiling**: the type says `string`, the value
    is a `Date`, and nothing reports it. Drop the override and take the table's own
    type.
  - **Code that assumed `addedAt` / `completedAt` is always present.** They are
    `Date | null` at the column now, because an unreadable value reads as `null`
    rather than as an `Invalid Date`. Read rows through the store, or through the
    exported `reviveIdentityRow` / `reviveSessionRow`, and the fallback to the row's
    `createdAt` puts a real `Date` back.

  Anything going through `createSqlStores` or the `drizzle*Storage` helpers is
  unaffected — those already revived, which is why the mismatch stayed hidden.

  The parsers are exported from `@gentleduck/auth/adapters/sql` (`storedDate`,
  `parseProviders`, `parseFactors`, `parseActingAs`, `fromJsonColumn`,
  `isProviderLink`, `isFactor`, `reviveIdentityRow`, `reviveSessionRow`, and the
  `StoredProviderLink` / `StoredFactor` types), and the wire-side converters from
  `@gentleduck/auth/client/vanilla` (`reviveSession`, `reviveIdentity`,
  `reviveSessionResult`), so an app reading these tables or calling `/session`
  directly can use the same conversion the adapters do instead of hand-rolling one.

## 5.6.0

### Minor Changes

- The client hands back the `Date`s its types promise, and the wire shape is now written down so it cannot drift again.

  `Response.json` is `JSON.stringify`, so every `Date` on a session or identity row left the server as an ISO string. `Sessions.Me` and `Identities.Me` declare all of them as `Date`, and a cast at the end of `getSession` stopped `tsc` from noticing. `session.expiresAt.getTime()` threw; `session.expiresAt < new Date()` compared a string to a Date and was always `false`, so a session never looked expired. `getSession` now revives `createdAt`, `rotatedAt`, `expiresAt`, `absoluteExpiresAt`, `factors[].completedAt`, `actingAs.startedAt`/`.expiresAt`, `createdAt`/`updatedAt`/`deletedAt` and `providers[].addedAt`. The react, vue, solid and svelte clients all wrap this one, so they inherit it.

  Fields are named, not sniffed by shape: `identity.profile` is the consumer's own data and is left untouched. A value that will not parse stays the string it arrived as rather than becoming an `Invalid Date`, which would satisfy `instanceof Date` and compare `false` against everything.

  New: `VanillaClient.Serialized<T>`, `SerializedIdentity` and `SerializedSessionResult` describe a row as it actually crosses HTTP. `Serialized<T>` is not assignable to `T`, so revival is the only route between the two and skipping it is a compile error — the previous version was correct only by convention, which is what let this ship.

  Also fixed on the same path: an enveloped-free `200` with an empty body parses to `null`, and that `null` was returned as `data` under a signature promising a `SessionResult`. It now resolves to `{ session: null, identity: null }`.

  The OpenAPI `Session` schema had the same disagreement from the other side: `expiresAt`, `absoluteExpiresAt` and `factors[].completedAt` were documented as `integer` when the handler sends ISO strings, so every generated client typed them `number` and a response validator would reject a valid reply. They are now `string` / `format: date-time`, `createdAt` and `rotatedAt` are documented too, and `tenantId` is `['string','null']` - it is `null` on every session of a single-tenant deployment. A test serialises a real row and checks each documented field against it, so the spec cannot drift from the wire again.

### Patch Changes

- Type-consistency pass: the package now reads untyped shapes one way, and the assertions that were left are the two that cannot be avoided.

  **Three dead casts in the drizzle adapters.** `drizzleSqliteStorage` and `drizzleMysqlStorage` laundered their bridge with `as unknown as SqlBridge.Me<Profile>` and pg used a single `as`, under a comment claiming the cast asserted the concrete `Profile` shape. It never did: `createDrizzle*Bridge` is already generic and already returns `SqlBridge.Me<Profile>`. All three now pass the type argument explicitly and assert nothing, so a future divergence between a bridge and the store contract is a compile error instead of being swallowed - which is exactly what a double cast had been positioned to hide.

  **`mfa.ts` read credential metadata three ways in one file.** `verifyTotp` and `hasTotp` used the shared `isProfileBooleanTrue` reader; `confirmTotpEnrollment`, the TOTP replay guard and the AAL-3 passkey check cast `metadata` straight to an interface. The casts happened to be safe - each compared strictly - except the replay guard, which read `lastTotpStep` through `typeof x === 'number'`. That accepts `NaN`, and `step <= NaN` is `false`, so a `NaN` there would have waved a TOTP replay through. All three now use the shared readers.

  New: `getProfileNumber` and `isProfileBooleanFalse` alongside the existing credential predicates. `getProfileNumber` rejects `NaN` and `Infinity` rather than returning a number that loses every comparison. `isProfileBooleanFalse` is deliberately not the negation of `isProfileBooleanTrue` - an absent key is neither, which is what tells "explicitly not yet confirmed" apart from "never had the field".

  **The compliance harness had 68 identical casts.** `runIdentityStoreCompliance` is generic over `P`, so a profile literal was not assignable to it and every fixture wrote `{ email, username } as unknown as P`. Every adapter instantiates the suite with the same two keys and the suite exercises no others, so that is now one documented assertion in one helper instead of sixty-eight scattered ones.

  Outside two dynamic `import()` calls for optional peer dependencies, no `as unknown as` remains in the package. Production code has no `any` and no `@ts-expect-error`.

## 5.5.1

### Minor Changes

- Audit round: captcha reaches the engine, three config keys stop being dropped on the floor, and the client stops handing back strings where the types promise `Date`.

  Every entry below this one in the release notes came out of the same sweep. The shape that
  recurs: something the type system already promised, that no code path actually delivered — a
  config key copied across by hand and forgotten, an option declared on the wrong half of an
  interface, a field a projection never populated, a `Date` that survived `JSON.stringify` as a
  string. None of it failed loudly, which is why it lasted.

  **Two signatures gained required arguments.** `beginPasskeyRegistration` now takes
  `credentialStore` and `tenant` — what it needs to read the identity's live passkeys and send
  `excludeCredentials`; `completePasskeyRegistration` already took both. `authRefreshoauthToken`
  now requires the `identities` probe, so a refresh token cannot outlive the identity behind it.
  Both are a compile error to miss, and both arguments are already on hand wherever the library
  itself calls them.

  The captcha default refuses rather than passes, so a host that never configured one sees no
  behaviour change unless it was relying on an unconfigured verifier to succeed — which is the
  thing being fixed.

- `cancelAccountDeletion` gains the user's route: a single-use undo token.

  Until now it had exactly one gate — a mandatory `authorize(identityId)` callback. That is
  the _operator's_ route. A user clicking "undo" in their mail has the mail and no admin
  rights, so the grace window that `completeAccountDeletion` advertises as `restorableUntil`
  was reachable only by opening a support ticket.

  `completeAccountDeletion` now mints an undo token after the soft delete lands — hashed,
  single-use, `kind: 'recovery'` under `purpose: 'account-deletion-cancel'`, expiring at
  exactly `restorableUntil`. Plaintext comes back once as `cancellationToken`. Pass the new
  optional `channels` (and `channel` / `callbackPath`) and the library mails the undo link
  under `templateId: 'account-deletion-cancel'`; omit them and delivery is yours. A host
  that does not want undo simply drops the token — nobody else ever holds the plaintext.

  `cancelAccountDeletion` takes one gate or the other:

  ```ts
  await auth.flows.cancelAccountDeletion({ token }); // the user
  await auth.flows.cancelAccountDeletion({ identityId, authorize }); // an operator
  ```

  Both, or neither, is `AUTH_MISCONFIGURED`. Resolving "both" in favour of one would mean a
  bad token silently falling back to a callback that says yes, and which gate applied would
  depend on a precedence rule invisible at the call site — the exact ambiguity this function
  used to be when it took an id and no gate at all. The token names its own subject, so no
  `identityId` accompanies it and an undo link cannot be pointed at another account.

  **Breaking.**

  - `Flows.AccountDeletionCancelInput` is now a union of `AccountDeletionCancelByToken` and
    `AccountDeletionCancelByAuthorize`. Existing `{ identityId, authorize }` callers are
    unchanged; callers that spread a wider object may need to narrow it.
  - `completeAccountDeletion` returns an extra `cancellationToken` field and writes one extra
    credential row per deletion.
  - `'account-deletion-cancel'` is a seventh `recovery` purpose. Anything reading
    `kind: 'recovery'` without filtering on `metadata.purpose` now sees one more row — see
    `RECOVERY_PURPOSES`.

- ec9629b: Provenance: audit columns that the API could not fill are now filled, and the ones that could only ever repeat another column are gone.

  `auth_identities`, `auth_credentials` and `auth_sessions` have declared `created_by` and `updated_by` since 5.x. Nothing in the package wrote them and they were not on the row types, so every row in every deployment carried NULL provenance — the schema promised an audit trail the API could not produce.

  **The ambient actor context** (mirrors the existing tenant one):

  ```ts
  import { withActor } from "@gentleduck/auth";

  await withActor(req.user.id, () =>
    auth.identities.update(id, patch, version)
  );
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
  - `restoreMany` now reports _which_ rule refused each row instead of guessing. It previously labelled every refusal `email-taken`, because that was the only clash there was; a provider clash would have arrived under the wrong reason.
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

- b06c50b: `cancelAccountDeletion` requires an `authorize` callback.

  It checked that `identityId` was a plausible string and then restored the account. No token, no session, no callback. Anyone who could reach the function un-deleted any account by id — including one deleted deliberately, by a user who wanted it gone.

  Every sibling in that flow is gated: `completeAccountDeletion` requires a single-use token, `impersonate` refuses to run without an `authorize` callback. This one was gated by nothing, and its own docstring called it an "optional admin cancel route" — an assumption the signature neither stated nor enforced.

  ```ts
  await auth.flows.cancelAccountDeletion({
    identityId,
    authorize: async (id) => currentUser.isAdmin && currentUser.canRestore(id),
  });
  ```

  - **Mandatory, not optional.** There is no default the library could pick that is safe; only the host knows who is asking. Required in the type, so every existing call site fails to compile until it says who may cancel.
  - **Checked before any read or write.** A refusal never reaches the store, so it cannot be observed as a restore-then-undo or timed against one.
  - **A refusal reports `AUTH_UNAUTHENTICATED`** — the same code an unknown identity gets. Distinguishing them would turn the endpoint into a way to ask which accounts are sitting in the deletion grace window.
  - **A missing callback is `AUTH_MISCONFIGURED`.** TypeScript refuses the call, but a JavaScript host — or an options object built from parsed input — reaches it anyway, and a missing gate must not read as permission granted.
  - The callback receives the **id**, not the identity: the row is soft-deleted at that point and cannot be loaded. Resolve the caller from your own request context.

  **Breaking:** `Flows.AccountDeletionCancelInput` gains a required `authorize: (identityId: string) => Promise<boolean>`. Every call site must supply it.

  **Not covered:** a cancellation _token_, for a user clicking "undo" in an email without admin rights. Nothing issues one today — `requestAccountDeletion` mints a deletion token that `completeAccountDeletion` consumes — so that path needs a second credential with its own TTL, channel and template. Until it exists, a user-facing undo link is the host's to authorize like any other route.

- `auth.captcha` exists, and refuses instead of passing when it was never configured.

  `Engine.Cfg` had no `captcha` key at all, so a host that wanted a challenge kept a second
  verifier next to the engine with its own wiring, and `auth.captcha` was `undefined`. It is
  now a first-class member: `createAuth({ captcha: authTurnstileVerifier({ secret }) })`, read
  back as `auth.captcha`.

  Unconfigured, `auth.captcha` is an `AuthUnconfiguredCaptchaVerifier` — every call answers
  `{ success: false, errorCodes: ['captcha-not-configured'] }`. Deliberately not
  `AuthNullCaptchaVerifier`, which always passes and ships for tests: a host writes
  `if (!(await auth.captcha.verify(...)).success) throw`, deploys with the secret unset, and an
  always-pass default lets every bot through while the code reads as though a captcha is
  enforced. Pass `authNullCaptchaVerifier()` to opt into always-pass. Both, plus the
  Turnstile / hCaptcha / reCAPTCHA v3 verifiers, are exported from `@gentleduck/auth/core`.

  **Also fixed:** `createAuth` copied engine-config keys across by hand and dropped the ones
  nobody remembered to add. `AuthDefine.Cfg` inherits them from `Engine.Cfg`, so a dropped key
  still type-checks at the call site and then silently does nothing. `resolveActor` was one:
  a host that wired an actor resolver the documented way wrote `created_by` / `updated_by` /
  `deleted_by` as NULL, which is the audit trail going missing for exactly the caller who took
  the trouble to configure one. `captcha` would have been the next. `createAuth` now spreads
  its config into the engine, so it cannot forget a key that is added later.

- caf7ddf: The rest of the critical and high findings in `core/flows`: an enumeration oracle, a delete that took three other flows' tokens with it, a signup that produced rows Postgres refuses, and a signup with no rate limit.

  **`requestPasswordReset` no longer answers, by clock or by error, whether an address is registered.**

  The unknown-address branch was a token gesture — one `sha256` — against a write and two reads on the known one. Separable by response time from anywhere. The library already had the correct version of this defence in `passwords.ts`, which runs a full hash against `NO_IDENTITY_SENTINEL` so the unknown path costs what the real one costs; the reset flow gestured at it without achieving it.

  Both branches now mint a token, hash it, and make the same three store calls in the same order, against the same sentinel. What could not be mirrored is the write — `auth_credentials.identity_id` is a foreign key, so there is no row to hang a decoy on — leaving one write against one read on the same table, down from one hash against three round-trips. The residue is pinned as a `FINDING:` rather than papered over.

  The louder half was not a timing signal at all: a channel that was not configured **threw** for an address that exists and returned `{ok:true}` for one that does not, saying it in plain language in the response body. The channel check moved above the identity lookup, so a wiring fault is a wiring fault regardless of who asked.

  One consequence worth stating: `requireMfa()` now runs on both branches, so a deployment with no MFA provider gets `AUTH_PROVIDER_NOT_REGISTERED` from either — the flow has always needed the provider for a known address, and the asymmetry was itself the oracle.

  **`requestEmailVerification` no longer voids three other flows' tokens.**

  It ran `deleteByKind(identityId, 'recovery')`. Four different flows share `kind: 'recovery'` — password-reset tokens, email-verification tokens, account-deletion tokens, and signup-flow state — and they are told apart only by a metadata field, which `deleteByKind` cannot read. So asking for a verification mail silently destroyed an in-flight password reset, a pending deletion confirmation, and an in-progress signup, stranding the user with a flow token that no longer resolved.

  Now it lists the identity's `recovery` rows and deletes only those whose purpose is `email-verification` — the same list-filter-delete `requestAccountDeletion` already used. It still replaces its own stale token, so two requests never leave two live links.

  **One discriminator, written by everything.** That fix is only correct if every flow supplies a purpose, and two did not: signup and password-reset wrote `metadata.kind` while `getCredentialPurpose()` — the helper every guard and every delete reads — reads `metadata.purpose`, and so returned `undefined` for both. All four now write `purpose`, and the two flows that reached into `metadata.kind` by hand read the helper instead.

  **`beginSignUp` builds a profile the library's own Postgres adapter accepts.**

  `Identities.ProfileMetadataBase` requires `username`. duck-auth's pg schema enforces it with `chk_auth_identities_profile_shape` plus a unique index on `lower(profile->>'username')`. And `beginSignUp` built `{ ...initialProfile, email }` — no username — then cast past its own type with `as unknown as Profile`. Since `initialProfile` is optional, `beginSignUp({ email })`, the documented happy path, produced an INSERT the library's own adapter rejects. Nothing caught it because the sqlite conformance DDL states in its own comment that it omits CHECK constraints, and memory and Redis have no schema at all.

  `username` is now derived from the address when the caller supplies none, and the double cast is gone. From the whole address rather than its local part: `username` carries a unique index too, so deriving `sam` would refuse the next `sam@b.com` because `sam@a.com` signed up first — a collision on a handle neither user chose.

  **`beginSignUp` consumes the rate limiter.** It was the only flow in the unit that never did; password-reset, email-verification and account-deletion all do. One unauthenticated request equalled one permanent identity row, unbounded. Keyed per canonical address, so hammering one victim's address is what gets capped.

  **Breaking:**

  - `beginSignUp` throws `AUTH_RATE_LIMITED` when the limiter trips. A host with a tight limiter and a signup retry loop will start seeing it.
  - `beginSignUp` writes a `username` into the profile when `initialProfile` omits one. Code asserting the profile has exactly the keys it passed will see one more.
  - Credential rows for password-reset and signup-flow state carry `metadata.purpose` instead of `metadata.kind`. **There is no fallback reader**: a token minted by the previous version resolves to no purpose and is refused as invalid. Both are 30-minute-TTL rows, so the exposure is one deployment window, and the failure direction is closed.
  - `requestPasswordReset` throws `AUTH_MISCONFIGURED` for a missing channel even when the address does not exist, and `AUTH_PROVIDER_NOT_REGISTERED` when the MFA provider is absent, on both branches.

  **Still open — F21's other half.** The rate limit caps how fast identities appear; it does not stop one appearing for an address nobody proved they own, so account pre-emption and the duplicate-address refusal remain. The recommended fix — hold signup state in the credentials store and create the identity at `completeSignUp` — cannot be built, because `fk_auth_credentials_identity` requires the row that fix defers, and `Provider.Context` carries no other store that could hold it. That makes it a schema decision rather than a flow one. Both halves are pinned as `FINDING:` tests.

- The fifteen medium and low findings left open in `core/flows` — and one critical that closing them turned up.

  **The MFA gate on `completePasswordReset` never checked whose session it was handed.**

  ```ts
  if (await hasTotp(row.identityId)) {
    const s = await sessions.getBySid(input.currentSid);
    if (!s || s.aal < 2 || !s.fresh)
      throw new AuthError("AUTH_RECOVERY_REQUIRES_MFA");
  }
  ```

  Nothing bound `s.identityId` to `row.identityId`. An attacker holding a victim's reset token — which is the exact situation the MFA requirement exists for — passed **their own** fresh AAL 2 session and the gate opened. Any account with a second factor was resettable by anyone with a second factor of their own, on any account.

  The session is now resolved once and only counts when it belongs to the identity the token names. This was not in the audit; it sat three lines from a finding that was, and was missed because a step-up check reads as being about the caller. Here the caller and the subject are different people by construction.

  **`releaseImpersonation` logged the operator out instead of ending the impersonation.**

  It revoked the impersonation session and called `transport.revoke()`, which clears the bearer outright. The real session that `impersonate-start` deliberately keeps alive is no help — `impersonate` overwrote the cookie with the impersonation sid, so its plaintext is gone from the client and nothing can present it again.

  It now routes through the `impersonate-release` rotation purpose, which had sat unused in the matrix since the matrix was written with exactly the semantics needed: mint, then delete the sid that was presented. The operator gets a session of their own back.

  **Breaking:** the return type is now `{ session, sid, intents }` and carries an `issue` intent rather than a `revoke`. `session` is `null` and `sid` is `''` only when the operator's own identity is gone, in which case the bearer is cleared as before.

  **Impersonation sessions no longer claim the operator's authentication.**

  `aal` and `factors` describe what a session's _subject_ did to prove they are there, and the subject of an impersonation session is the target, who did nothing. Copying the admin's verbatim wrote the admin's TOTP, at the admin's `completedAt`, onto the target's session — so any policy asking "has this user recently passed a second factor" got the wrong person's answer for as long as the impersonation lasted.

  Both the impersonation session and the session `releaseImpersonation` hands back start at `aal: 1` with no factors. The operator's assurance is not discarded, it is spent: it is the input to `authorize(realSession, targetIdentityId)`, which is where an operator-AAL requirement belongs. **Behavioural** — hosts that read `aal` off an impersonation session will now see 1, and an operator returning to privileged work steps up again.

  **`linkProvider` now requires an `authorize` callback.**

  `providerSub` arrives as a plain string. Nothing about it is verifiable from inside duck-auth. Wired to a completed OAuth callback it is exactly right; wired to a route that trusts a request body, an attacker links their own provider account to a victim's identity and signs in as them from then on. The signature left that difference unstated, so both readings looked like correct usage.

  ```ts
  await auth.flows.linkProvider({
    identityId,
    providerId: "authGoogle",
    providerSub: claims.sub,
    authorize: async ({ identity, providerId, providerSub }) =>
      /* your check */ true,
  });
  ```

  **Breaking.** A missing callback is `AUTH_MISCONFIGURED`; a refusal is `AUTH_PROVIDER_FAILED` and writes nothing. Same shape `impersonate` and `cancelAccountDeletion` already use for the same class of problem, and the same warning applies: never `async () => true`.

  **Unlinking a provider is audited, and can no longer race itself into a lockout.**

  `identity.linked` existed; `identity.unlinked` did not. Removing an authentication factor — the write an account takeover performs to close the real owner's way back in — left no trace at all. The new event carries `allowedLockout` so an override is visible in the trail, and is registered for webhooks and audit envelopes.

  The lockout guard was also a read followed by an unversioned write. Two concurrent unlinks of different providers each saw the other's link still present, each concluded a factor would survive, and both landed — an identity with no way back in, produced by a guard whose entire job was to prevent that. The question is now re-asked against the post-write row, and the loser puts its link back with the original `addedAt`. Both racers rolling back is possible and is the safe direction.

  **`completePasswordReset` ends sessions before it writes the password, and answers with intents.**

  The old order left a window with the new password live and the old sessions still open: if the revoke threw, whoever held a session the reset was meant to end kept it, and the account holder had no way to tell. Failing before the password write is the harmless direction — nothing has changed, and the user asks for another link.

  A caller who _is_ signed in now rotates through `rotateOrCreate({ purpose: 'credential-change' })` rather than merely being swept, which puts the transition back on the single rotation path `sessions.ts` promises every privilege change takes. The ordinary email-link reset still sweeps: `credential-change` mints as well as revokes, and minting there would turn a reset link into a way to sign in.

  **Breaking:** the return type is now `{ ok: true; intents: Provider.Intent[] }`. `intents` is empty on the email-link path and carries a replacement bearer when the caller was signed in.

  A failed MFA gate is also bounded now. Consuming the token outright would break the documented flow — being refused, stepping up, and calling again with the _same_ token is how it is meant to work — so the gate is rate limited per token hash instead, and when the bucket is spent so is the token.

  **The password-reset row no longer duplicates the address.**

  `metadata` carried `{ purpose, email }`. Nothing read the address back — the flow resolves the identity from `row.identityId` — and it was a second copy of PII in a table `identities.erase` has no reason to sweep, so an erased account left its email sitting there until the row's TTL expired.

  **Signup state is bounded, atomic, and written through the facet.**

  - `profileMaxBytes` now applies to `flow.data` at `beginSignUp` and `advanceSignUp`, not only when it finally reaches an identity row. Flow state lives in credential metadata, which has no size limit of its own, for up to 24 hours and is re-read on every stage — a cap the profile only meets on its last hop is not a cap.
  - `advanceSignUp` was `rotate` → `revoke` → `upsert`: three writes, no transaction, and the middle one destroys the token. A failure after the revoke stranded the user mid-signup, and the recovery depended on `upsert` re-accepting a secret hash that had just been revoked. It is now `rotate` (with the row's own secret, so the compare-and-set survives without invalidating the token) then `patchMetadata`, one atomic merge.
  - `completeSignUp` writes through `identities.updateProfile` instead of the raw store, which also deleted a hand-rolled merge and its `as Profile`.
  - The rotation is `purpose: 'sign-up'`, a new entry in the matrix. `previousSid` is optional and most signups have no prior session, so calling every one of them a `guest-promotion` made the rotation log describe a transition that never happened.

  **Email verification.**

  - `IdentitiesImpl.markEmailVerified` reads its own expected version and retries once on `AUTH_STALE_WRITE`. The flow consumes the single-use token before this write, so a concurrent profile update used to surface a raw stale-write error with the token already spent and no second attempt for the user to make.
  - The rate limiter moved below the two early returns that send nothing. An unknown id and an already-verified address used to spend a real user's resend budget on a request that could never produce a message.

  **Also:** `IdentitiesImpl.assertProfileWithinCap` is public (and takes `unknown`) so callers staging profile data elsewhere can hold it to the same limit; `provider-link.flow.ts` builds one `Provider.Context` per call instead of two or three.

  Every fix is pinned in `src/core/flows/__tests__/flows-c6-open-findings.test.ts`, each written to fail against the pre-fix code, and four of them again on real Postgres in `flows.e2e.test.ts`.

- b06c50b: Expired sessions are no longer accepted at any privileged gate.

  `SessionsImpl.getBySid` hashed the sid and returned whatever the store had — no expiry check at all. `resolveBySid`, in the same file, checks both deadlines and deletes the row. Two reads that look alike, one of them unsafe, and four call sites depended on the unsafe one:

  - **`completeStepUp`** — an expired sid completed a step-up, and `rotateOrCreate` minted a brand new live session from the dead one. Presenting an expired sid did not merely pass the gate; it resurrected the session.
  - **`impersonate`** — an expired admin session could start an impersonation, and the app's own `authorize(real, target)` callback was handed that dead session to judge.
  - **`completePasswordReset`** — a stale session with `aal >= 2` satisfied the MFA gate, so a valid reset token plus a long-dead session changed the password with no live MFA behind it.
  - The Redis store serving rows past `expiresAt` was correct layering — expiry is the facet's policy, not the store's — but this is what made it reachable.

  `getBySid` now refuses a session past either deadline and deletes the row, the same side effect `resolveBySid` has. Folded into the read rather than patched at each call site, so the fifth caller added later cannot reintroduce it.

  **`fresh` is computed, not read.** It was a persisted boolean that only `touch()` ever refreshed, so a session written `fresh: true` and never touched still claimed freshness weeks later — and the password-reset gate reads exactly that field. `getBySid` now derives it from `rotatedAt` and `freshnessMs`.

  **Also:** the date narrowing copy-pasted across `getBySid`, `touch` and `resolveBySid` is one `isSessionExpired` helper now, which removed the four `as number` casts those copies carried. It fails closed on a non-finite or missing deadline, because `NaN < now` is `false` — a lenient read keeps a should-be-dead session alive forever.

  **Breaking:**

  - `getBySid` returns `null` for an expired session instead of the row, and **deletes** it. Code relying on it to read expired rows must go to `Sessions.Store.getByHash` directly.
  - The `fresh` field on a session returned by `getBySid` is now computed from `rotatedAt`. A session that was stored `fresh: true` but rotated longer ago than `freshnessMs` now reports `false` — which is what the gates guarding password changes and step-up were always meant to see.
  - New exports `isSessionExpired` and `isSessionFresh` from `~/core/sessions`.

  **`resolveBySid` recomputes it too.** It takes an optional `freshnessMs` on its options bag, defaulting to `DEFAULT_SESSION_CONFIG.freshnessMs`, and `AuthEngine.resolveSession` passes its own — so the cookie path now means the same thing by `session.fresh` that the JWT path has always meant, which recomputes from `rotatedAt` on every verify.

  **And `fresh` turned out to be two claims in one column.** Recomputing purely from the clock broke a step-up case, and the failure was correct: `rotateOrCreate({ purpose: 'step-up' })` demotes the session being stepped up _from_ by writing `fresh: false` onto a row whose `rotatedAt` is seconds old. The clock half decays; the stored half revokes. `isSessionFresh` is now the AND of both — a stored `false` is sticky, so freshness expires with time and can be withdrawn early, but storage can never grant it.

- `strict()` demanded a `lockout` handler for an event nothing in the library emitted.

  `engine.strict.ts` refuses to boot production unless something is subscribed to
  `lockout`. Nothing ever published one. Eight limiter guards — password sign-in,
  magic-link, api-key, signup, password reset (request and MFA gate), email
  verification, account deletion — each computed a `Retry-After`, threw
  `AUTH_RATE_LIMITED`, and told nobody. `telemetry/otel` counts `lockout` and
  `webhooks` forwards it; both had been waiting on a publisher since they were
  written. Operators were made to wire a handler for an event that could not arrive,
  which is worse than no check at all: it reads as coverage.

  All eight now route through one helper, `refuseRateLimited`, which emits and then
  throws. A refusal that knows whose account is under pressure names it; one that does
  not stays silent, because `lockout` carries `{ identityId, until }` and an emit with
  no subject is a page nobody can act on.

  **Emits:** password sign-in, `requestEmailVerification`, `requestAccountDeletion`,
  and the `completePasswordReset` MFA gate.

  **Stays silent, deliberately:** `api-key` (the only route from a token-hash bucket to
  a subject is the verification the guard exists to shed), `magic-link` and
  `requestPasswordReset` (resolving the address means running host code on every
  refused request to an unauthenticated endpoint, and a spent mail bucket blocks a
  delivery rather than an authentication), and `beginSignUp` (no account exists behind
  the address yet).

  Two ordering changes came with it:

  - `authPassword.complete` now looks the identity up **before** consuming the limiter.
    This is the bucket `lockout` exists for, and it is the one site that pays for its
    subject — a refused request costs one indexed read the limiter used to shed, still
    a fraction of the argon2 verification the guard is actually there to stop. The
    happy path is unchanged; it made the same call one line later.
  - `requestAccountDeletion` consumes the limiter **below** the identity lookup, the
    same reorder `requestEmailVerification` already had. Above it, an id with no row
    behind it spent a bucket and would now have paged an operator about an account that
    does not exist.

  Two bugs fell out of collapsing eight copies into one:

  - **`Retry-After: 0`.** Seven of the eight used `Math.max(0, …)`, which tells a
    client to retry immediately for the last fraction of a second of a window — from
    the guard whose entire purpose is to say do not. The floor is `1` everywhere now,
    the value `api-key` alone already used.
  - **A broken `resetAt` defeated the limit.** Every copy called
    `limited.resetAt.getTime()` unguarded, so a limiter adapter returning a number
    raised a `TypeError` and the caller saw a 500 instead of a 429 — the limit did not
    apply. An invalid `Date` produced `retryAfter: NaN`. The helper reads it
    defensively and still refuses.

- `authRefreshoauthToken` requires the `identities` probe instead of asking nicely for it.

  It was optional, documented as "should be supplied". Nothing in the library calls this
  function — refresh-token rotation is invoked by the host directly — so there was no wiring
  to supply it, and the only guidance a caller got was a signature saying the safe argument
  was opt-in. Omitted, a refresh mints new tokens for an identity that has since been deleted
  and hands its id back, because nothing on the credential-first path looks at the identity.

  `apiKeyProvider` passes `stores.identities` unconditionally for the identical check. This
  makes the same guarantee unskippable. A client-credentials grant, which has no
  `row.identityId`, still skips the lookup.

- `beginPasskeyRegistration` tells the authenticator which keys the identity already has.

  `excludeCredentials` — WebAuthn's mechanism for "this account is already enrolled on this
  authenticator, do not mint a second key" — was declared on `Passkey.RegistrationOptionsInput`
  and on `Passkey.RegistrationOptions` from the start, and never once populated. Every
  registration ceremony went out with the field absent, so a user who ran registration twice on
  the same device got two credentials for the same account with nothing to tell them apart:
  same name, same device, and no way to know which one to prune.

  **Breaking:** `beginPasskeyRegistration`'s second argument now requires `credentialStore` and
  `tenant`, matching `completePasskeyRegistration`, which already took both. That is what the
  ceremony needs to read the identity's live passkeys.

  Revoked rows are deliberately left out of the exclusion list: a revoked passkey is one the
  user asked to be rid of, and re-enrolling that authenticator is the documented way back in.
  Transports are sent when the authenticator reported them and omitted rather than guessed when
  it did not.

  Found by sweeping for option keys that a type declares and no implementation ever reads — the
  same sweep that turned up `onFederationConflict`.

- 11394fc: The public surface now names what it returns, and a post-commit drain no longer reports a committed write as a failure.

  **`pending.flush()` never rejects.** It resolves with `{ published, failed: Error[] }`.

  `flush` runs after the caller's transaction has committed and empties the buffer whether or not a listener threw, so a rejection asked the caller to handle a failure with nothing left to retry — and the natural handling, letting it propagate, answered a committed write with a 500 whose one promise, that the write did not happen, was false. The write happened; some announcement of it did not. Those are different facts and callers need to tell them apart, log the second, and still answer 200. A thrown non-`Error` arrives as an `Error` with the original on `cause`, so `failed` is always loggable.

  Callers who want the old behaviour can write `if (failed.length) throw new AggregateError(failed)`. The reverse was not available, which is why this changed.

  **`identities.restore()` returns `Me | null`.** One rule now covers all three lifecycle writes: `null` means the id matched nothing — the same outcome `softDelete` and `erase` already reported that way — and a throw means a row _was_ matched and a named rule refused it (`AUTH_GRACE_EXPIRED`, `AUTH_EMAIL_TAKEN`). `restore` was typed as though it could not miss, which told you which outcome the author remembered rather than which outcomes exist. It threw `AUTH_UNAUTHENTICATED` for an absent id; that path is now `null`.

  `flows.cancelAccountDeletion` is unchanged and still throws `AUTH_UNAUTHENTICATED`: at a flow boundary there is no account whose deletion could be cancelled, which is an error rather than data.

  **The root barrel re-exports the domain types.** `@gentleduck/auth` exported the engine and none of the types the engine returns, so naming the type of any return value meant a second import from `@gentleduck/auth/core`. `Identities`, `Sessions`, `Credential`, `Org`, `Events`, `Batch`, `Pending`, `Flows`, `Engine`, `Bound`, `Provider`, `Transport`, `TenantContext`, `Envelope`, `Anomaly`, `Compliance`, `Hijack`, `M2m`, `Operations`, `Kms` and `DataAtRest` are now reachable from the root. These are types only — the runtime surface is unchanged and still deliberately narrow.

  **`Identities` is exported under its own name, and `Identity` is gone.** `@gentleduck/auth/core` exported the namespace as `Identity`, so it read as `Identities` in every declaration, doc comment, internal signature and error message, and as `Identity` at the import site. There is now one name. Replace `import type { Identity } from '@gentleduck/auth/core'` with `Identities`; the members are unchanged, so the rest of each reference stays as it is.

  **`CHANGELOG.md` ships in the package.** The README links it and `files` did not include it, so on npm the link 404'd and the only way to see what a release contained was to diff two tarballs. `@gentleduck/iam` had the same gap and is fixed too.

- Backup codes no longer wipe the user's password reset, and no other recovery token is a second factor.

  `Credential.kind = 'recovery'` names six unrelated things — a password-reset token, a
  verification mail, a pending account deletion, an in-flight signup, an MFA backup code
  and a remembered device — and `kind` distinguishes none of them from each other.
  `metadata.purpose` is the real discriminator. The flows had already learned this; both
  backup-code implementations had not.

  **Deletes.** `BackupCodesFacet.generate`, `BackupCodesFacet.revokeAll` and
  `MfaImpl.regenerateBackupCodes` each called `deleteByKind(identityId, 'recovery')`,
  which reads as "replace the codes I own" and means "delete all six". Regenerating backup
  codes therefore voided whatever the identity was holding: the reset link sitting in their
  inbox, their verification mail, their pending deletion request, their half-finished
  signup, and every device they had asked the site to remember. All three now delete by
  purpose.

  **Reads.** `BackupCodesFacet.verify` and `MfaImpl.verifyBackupCode` hashed the submitted
  code and compared it against every `recovery` row, so the other five token families were
  candidate second factors. Not practically reachable — both verifiers case-fold before
  hashing (`toUpperCase` and `toLowerCase` respectively) while the other five store the
  hash of a raw base64url token, so a collision needs a token with no letter of the wrong
  case — but the guard was case-folding luck, not a check. Both now filter on purpose.
  `BackupCodesFacet.remaining` counted the same six families, so "you have N backup codes
  left" counted reset tokens.

  **Breaking.** Backup-code rows written before this release carry no
  `metadata.purpose` and will not verify. Have affected users regenerate their codes.
  `MfaImpl.regenerateBackupCodes` and `BackupCodesFacet.generate` both mint a fresh,
  correctly stamped set.

  New: `RECOVERY_PURPOSES` (the six names, in one place) and
  `deleteCredentialsByPurpose(store, identityId, kind, purpose, ctx)`, which is the
  list-and-delete `requestEmailVerification` and `requestAccountDeletion` were each doing
  inline. Both now call it.

  The two backup-code implementations remain independent and mutually incompatible —
  `MfaImpl` hashes `code.toLowerCase()`, `BackupCodesFacet` hashes an upper-cased,
  hyphenated form — so codes minted by one still cannot be verified by the other. Sharing
  a purpose does not make them share a format; that is a separate change.

- 01eda74: The Redis session store: a parser that threw instead of failing closed, a create that could leave a session no revocation could reach, and a `gc` that never took the lease its contract promised.

  **`parseStoredSession` never throws now — and stops losing factors quietly.**

  Its whole contract is that a corrupt or tampered row reads as "no session" rather than taking a request down. It did not hold. `Array.isArray` narrowed `factors` to `any[]`, so the filter read `.method` off whatever was in the array; a single `null` element threw, outside the `try/catch` that guards only `JSON.parse`. `getByHash` is on the path of every authed request for that session, so one bad blob was a permanent 500 — and `listByIdentity`, which parses in a loop, went down with it.

  Every _other_ malformed shape was the quieter half and the more dangerous one: it was dropped. A row claiming `aal: 2` came back carrying no factors at all, and step-up logic reads that list as authoritative.

  - A structurally broken entry — `null`, a primitive, no `method` — now rejects the whole row. That is corruption, and a session we cannot read is not a session we should serve.
  - An unknown but well-formed method is still skipped, not rejected: that is what a newer writer adding a factor method produces, and an older reader must not choke on it.
  - The 16-element `factors` cap that `sessions.create` and `parseJwtPayload` both apply is now enforced here too. This reader was the one door in that had no cap.
  - A malformed `actingAs` envelope is refused rather than degraded to `null`. Degrading it lost both halves of what the envelope is for — the audit trail naming the real actor, and the expiry bounding the impersonation window — and left the row reading as an ordinary session belonging to the person being impersonated.

  **`create` writes the index before the record.** The two writes are separate round-trips. A failure between them used to leave a session that authenticates fine but sits in no identity index: `listByIdentity` cannot see it and `deleteAllForIdentity` cannot delete it, so it survives the password change or ban that was supposed to end it. Reversing the order alone is not enough and would have made things worse — a concurrent `listByIdentity` pruned the entry inside the gap, and a record no index names is unreachable forever. So `listByIdentity` no longer prunes: a missing record may be a create still in flight, and only that create knows. A failed record write compensates its index entry, but only when `sadd` reports it actually added one — otherwise a duplicate `create` would unindex whichever session won the race.

  **`gc` is driven by an expiry index instead of walking every session.** The sweep used to `SCAN` every `{prefix}:idx:identity:*` key, read every member's record, parse it, and compare two dates — O(every session that exists) per cycle, on a schedule, with a `get` and a `JSON.parse` for each one. It also could not sweep guest sessions at all: they carry no `identityId`, sit in no index, and so were reachable only by their key TTL, which tracks `absoluteExpiresAt` and therefore never enforced the sliding `expiresAt` on them.

  There is now a single deployment-wide sorted set, `{prefix}:exp`, whose members are `sessionId:identityId` scored by whichever deadline comes first. `gc` pages it with `ZRANGEBYSCORE -inf <now> LIMIT`, so a cycle costs one range query plus the rows that are genuinely due — nothing proportional to the sessions that are still live. Because the member carries the owning identity, a row is deleted and dropped from its identity index **without its body ever being read**, and a guest session is swept like any other.

  The write paths keep the index in step: `create` adds the member after the record lands (an `nx` collision must not re-score the live session already under that id, and a create that cannot be scheduled unwinds itself), `update` re-scores before writing so a renewal is never swept on its old deadline and moves the member when the session changes identity, and `delete` / `deleteAllForIdentity` retire members directly rather than leaving them to come due.

  This also closes the race the index walk could only narrow. That sweep met index entries naming records that had not landed yet and had to re-read to guess whether they were orphans; a session earns an expiry member only once its record exists, so a create in flight is invisible to `gc` by construction. The confirming second read is gone with it. `create` now refuses a session id containing `:`, since that is where the member splits.

  **`gc` takes a distributed lease.** `Sessions.Store.gc` has been documented as "acquires distributed lease before running" since 5.x, and no implementation acquired anything — every instance in a fleet swept concurrently. Worse than the waste, an operator reading that line would reasonably conclude they did not need their own locking. `RedisSessionImpl` now takes `{prefix}:gc:lease` with SET NX and returns `{ deleted: 0 }` when it loses. The lease is left to expire rather than released in a `finally`: a sweep that outruns the window has already lost it, and deleting it then frees a lease the run no longer holds. New `gcLeaseSec` config, default 300s. The SQL store's `gc` is unaudited and was left alone; the contract's docstring now says what it actually guarantees instead of over-promising.

  **`_ttlFor` fails closed.** It assumed anything that was not a `Date` was a number, so an `absoluteExpiresAt` that arrived as an ISO string — what a JSON round-trip produces — made every step downstream `NaN`, and `{ ex: NaN }` reached the client. Some clients write that as a key with no expiry at all: an immortal session. It now parses through the same `parseStoredDate` the read path uses, so a serialised date yields the session's real TTL rather than the 30-day ceiling, and only a genuinely unparseable value falls back to the cap.

  **`listByIdentity` reads concurrently.** It awaited one `get` per session id in a loop. It backs the active-devices view and runs inside `revokeAllForIdentity`, so those were N sequential round-trips on a request path. Now `Promise.all` over the same `get` — no new client methods, since widening `RedisLike.Client` would force every adapter to implement more.

  **Also fixed here:**

  - The parser's `kind` and `aal` gates were written with `as` casts; they are `isSessionKind` / `isAal` predicates now, along with `isRecord` and `isFactorMethod` for the new checks.
  - A session-security e2e case read the clock four separate times to build one row, so `absoluteExpiresAt` and `expiresAt` could straddle a millisecond tick and invert — tripping `chk_auth_sessions_absolute_expires_after_expires` and reporting a working constraint as a broken write. Both such cases now take a single reading.
  - The identity compliance suite gave `restoreMany` a one-second grace window and then spent it on a create-and-erase round-trip against the real database. On a loaded MySQL container the window closed first, and correct behaviour was reported as a failure. The round-trip now happens before the clock starts, on the minute-long window the rest of the suite uses.

  **Breaking:**

  - Stored session rows that are structurally malformed — a broken `factors` entry, more than 16 factors, a partial `actingAs` — now resolve as `null` instead of resolving with the bad part silently removed. Sessions affected by this were already carrying data the library could not vouch for; they will need to sign in again.
  - `Sessions.Store.gc` implementations that can run on more than one instance are now required to serialise themselves. Nothing enforced this before because nothing did it.
  - **`RedisLike.Client` gains `zadd`, `zrem` and `zrangebyscore`.** A custom client implementing this interface by hand will not compile until it has them; `FakeRedis` and the bundled valkey/ioredis adapter already do. `@upstash/redis` and node-redis expose all three under those names.
  - **`RedisSessionImpl` claims a new key, `{prefix}:exp`.** A deployment that namespaces by prefix is unaffected; one sharing a database with other data should confirm that key is free.
  - **Sessions created before this release have no expiry member**, so `gc` will not sweep them — they fall back to their key TTL, which is what bounded them before this index existed, and their identity-index entries are cleared when that index key's own TTL lapses. They are otherwise fully usable, and any `update` schedules them. To sweep them promptly instead, backfill from the existing records once after deploying, or accept that they age out.
  - `RedisSessionImpl.create` now rejects a `session.id` containing `:` with `AUTH_MISCONFIGURED`. The sha-256 hashes the library generates never contain one; a deployment substituting its own id scheme must not use that character.

- Sessions can be read and revoked per tenant. They were the only tenant-scoped store
  with no tenant parameter.

  Every store meant to be tenant-scoped takes a `TenantContext` on every method —
  `Credential.Store` on all ten, `Org.Store` on all six. `Identities.Store` takes none
  and is deliberately global; the conformance suite says "identities are global" in as
  many words. Sessions sat between the two: a `tenantId` column that no method could
  select on, against a `TenantContext` docstring promising "stores receive it on every
  call".

  Because identities are global, one person is routinely a user of tenant A and of
  tenant B with every session hanging off one id. So `listByIdentity(identityId)` handed
  tenant A the IP, user-agent and existence of that person's tenant B sessions, and
  `deleteAllForIdentity(identityId)` — "sign out everywhere" — logged them out of tenant
  B when tenant A revoked. `resolveSession(req, { expectedTenantId })` does not cover it:
  it compares after the read and the option is optional, and `core/tenant/tenant.ts` says
  outright that "`withTenant` is a default, not a fence".

  `Sessions.Store.listByIdentity` and `deleteAllForIdentity` now take an optional
  `ctx: TenantContext`, as do `SessionsImpl.listForIdentity` and
  `SessionsImpl.revokeAllForIdentity`. Omitted, or carrying no `tenantId`, it means every
  tenant, so every existing caller keeps its current answer. Named, it matches exactly —
  which puts a global (`tenantId: null`) session outside a named tenant's scope, the same
  rule `Credential.Store` already follows.

  Implemented in all three stores. `SqlBridge.Session.listByIdentity` and
  `deleteAllForIdentity` take `tenantId: string | undefined`, mirroring the credential
  bridge — **a breaking change for anyone who implements the SQL bridge directly**; the
  shipped pg, sqlite and mysql adapters are updated. Two cases were added to
  `runSessionStoreCompliance`, so all five shipped stores are held to the rule and the
  pg, mysql, redis and valkey runs prove it against real servers.

  **Still global, deliberately:** the `credential-change` sweep in `rotateOrCreate` (a
  password belongs to the global identity, so changing it must end every session it could
  have opened), `revokeAllForIdentities` (scoping the loop fallback but not the optional
  set-based store form would make one call behave differently per adapter), and
  `identities.erase`.

  **Also fixed: `FakeRedis.del` ignored sets and sorted sets.** It deleted from its string
  map only, so dropping a set or zset key was a silent no-op — and the session store's
  index and expiry keys are exactly those types. `runSessionStoreCompliance` runs the whole
  store contract against `FakeRedis` in-process precisely to catch divergences, so any case
  asserting "the index key is gone" had been passing against a fake that never removed it.

  The Redis scoped delete `srem`s the ids it removed rather than `del`ing the index key:
  dropping the key would leave the sessions it spared alive and unreachable by every later
  read and sweep — signed in, with nothing able to sign them out.

- `beginSignUp` no longer lets anyone permanently claim someone else's address.

  It writes an `auth_identities` row for an address the caller has not proved they own.
  The unique index on email then means the real owner's signup collides with the squat
  and there is nothing they can do about it, ever — and the duplicate-email refusal
  answered "is this an account?" to anyone who asked.

  Deferring the identity until the address is verified — the obvious fix — is not
  buildable: `fk_auth_credentials_identity` is a NOT NULL foreign key to the very row that
  plan defers, so the credential holding the flow token has nowhere to live, and
  `Provider.Context` carries no other store that could host it.

  So the squat is disarmed rather than prevented. `beginSignUp` reclaims an existing row
  when, and only when, it is in exactly the state `beginSignUp` itself leaves behind:
  `emailVerified` false, no provider links, and no credential that is not a `signup-flow`
  token or already revoked. The previous flow's tokens are revoked, the profile becomes
  the new signup's, and the caller gets the row. An attacker parking on `victim@corp.com`
  no longer blocks its owner — the owner takes the parking spot.

  **The predicate is the safety argument, not a detail.** `completeSignUp` mints a session
  for the reclaimed identity, so a rule one notch looser would be account takeover rather
  than squat reclaim: an unverified account with a password set is somebody's, and so is
  one with a Google link or a TOTP secret. MFA backup codes are `kind: 'recovery'` under
  `purpose: 'mfa-backup-code'`, so they fail the `signup-flow` test and read as
  established, which is right. The credential check is
  deliberately unscoped — identities are global while credentials are not, so a
  tenant-scoped read would miss a password in another tenant and call an established
  account abandoned.

  **`completeSignUp` now records the verification the flow claimed.** Nothing in this flow
  ever wrote `emailVerified`, so an account created through the documented happy path
  stayed unverified for good. Harmless before; under the reclaim rule it would have left
  finished accounts reclaimable forever. When the `email-verified` stage is among the
  completed ones, the column is written, and the session is issued from the settled row.

  **Still open, deliberately.** The identity row is still written on an unauthenticated
  request — bounded by the `signup:begin:<address>` limiter, and no longer a claim. And an
  _established_ account still answers `AUTH_EMAIL_TAKEN`, because the address is unique
  and a second account for it cannot exist. Closing that needs what `requestPasswordReset`
  has — a channel to answer through, so the owner is mailed and every caller gets the same
  reply — and `beginSignUp` takes no channel.

- `completeStepUp` reads the second factor in the session's tenant, not in one the caller names.

  It took an optional `tenantId` that scoped the MFA credential read, while the session being
  stepped up carried a tenant of its own — and nothing bound the two. The default when
  `tenantId` was omitted made it worse: `{}`, an _unscoped_ read. Credentials are
  tenant-scoped and identities are not, so a TOTP secret or backup code enrolled in tenant B
  satisfied a step-up for a session in tenant A — a tenant that had never seen a factor for
  that identity, and whose `hasTotp` therefore never asked for one. Any policy gating admin
  work on `aal >= 2` accepted a factor its tenant had never issued.

  **Breaking:** `completeStepUp` no longer accepts `tenantId`. The factor is looked up in
  `session.tenantId` (unscoped for a global session, matching every other credential read),
  so there is no second input left to disagree with the session.

  Found by sweeping for the shape of F28 — a gate that resolves its scope or its subject from
  one input and acts on another, with nothing binding them. It was the only other live
  instance; `impersonate`, `signIn`, `linkProvider` and `releaseImpersonation` each bind
  their two inputs already.

- `onFederationConflict` is reachable from the six shipped OAuth providers.

  The policy that decides what happens when an OAuth profile's email already belongs to a
  local identity with no link to that provider — `'reject'`, `'link-if-verified'`, or a
  caller-supplied `(ctx) => 'link' | 'reject'` hook — was declared on `OAuth.Options`, read by
  `OProviderImpl`, and documented in full. It was also unreachable: `OptionsBase`, the type
  every shipped provider factory takes, never declared the key, and `oProvider` is not
  exported from any package entrypoint. So `google()`, `github()`, `linkedin()`,
  `microsoft()`, `discord()` and `apple()` were all hard-wired to `'reject'` with no way for a
  consumer to choose otherwise.

  `'reject'` is the safe direction, which is why nothing broke and nobody noticed — it made
  the feature dead rather than dangerous. `OptionsBase` now carries the key and all six
  factories forward it, so "merge after out-of-band confirmation" and "link when the IdP says
  the address is verified" are configurable rather than documentation for a branch no caller
  could reach. The default is unchanged.

  The policy branch also had no test of any kind; it now has five, driven through `google()`
  against a stubbed IdP.

### Patch Changes

- The client hands back real `Date`s, and `revoke()` says a key is revoked.

  `Sessions.Me` and `Identities.Me` declare `Date` for every deadline they carry. The vanilla
  client's `getSession()` did a bare `JSON.parse` of the response and handed the result back
  under those types, so every one of those fields was an ISO string wearing a `Date` annotation.
  The loud half was `session.expiresAt.getTime is not a function`. The quiet half was worse:
  `session.expiresAt > new Date()` compares a string against a Date, is always `false`, and a
  live session reads as expired with nothing thrown. All four framework clients (react, vue,
  svelte, solid) wrap the vanilla one, so all four had it.

  Revival happens once, in `getSession`, over a named list of fields — not by sniffing values
  for date-shaped strings, which would rewrite `identity.profile`, whose contents belong to the
  host app. A string that will not parse is left exactly as it arrived rather than promoted to
  an Invalid Date, which passes `instanceof Date` and compares `false` against everything.

  `ApiKeysFacet.revoke()` documents that it answers with "the key as it stands revoked". The
  projection behind it copied `createdAt`, `lastUsedAt` and `expiresAt` and dropped `revokedAt`,
  so `ApiKeys.ApiKey.revokedAt` was declared by the package and never once populated — a UI
  reading the answer back could not tell the revoked key from a live one.

  The three store-compliance suites now assert, on every read path, that each field is the type
  its row declares — including that a `Date` is a `Date` and not an Invalid one. That runs
  against every shipped backend: memory, drizzle sqlite/postgres/mysql, redis, valkey.

- Updated dependencies [70a9e4d]
- Updated dependencies [ff6f112]
- Updated dependencies [3de4298]
- Updated dependencies [8c131a4]
- Updated dependencies [3de4298]
  - @gentleduck/iam@5.8.1

## 5.4.1

### Patch Changes

- 11394fc: Adapter audit: batch outcomes name the rule that refused a row, and a soft-deleted account no longer holds a provider login hostage.

  **`Batch.FailureReason` gained `grace-expired` and `email-taken`.** `not-found` was reported for every row a `restoreMany` did not apply, including rows that were found and then refused by the grace window or by an address a live identity had taken since. A caller told `not-found` has no way to learn the id is still there and still restorable once the clash is resolved. Both batch paths were affected — the set-based SQL form and the loop fallback used by the memory and Redis stores. Consumers matching exhaustively on `FailureReason` will need the two new arms.

  **A soft-deleted row no longer holds its provider sub.** The cross-identity uniqueness guard counted hidden rows, but `findByProviderSub` ignores them, so a sub could be unreadable and unclaimable at the same time — a deleted account keeping someone's Google login forever. All four adapters now count live rows only, matching what the read side already did.

  **`restoreManyReturning` (SQL bridge) returns `{ candidates, restored }`.** Custom `SqlBridge` implementations need updating; the dialects shipped with the package already do. The candidate rows are what let the store report _why_ a row did not come back instead of guessing.

  `isRestorable` is exported from `@gentleduck/auth/adapters/sql`, so the batch and single-row paths cannot drift about when a grace window has closed.

## 5.4.0

### Minor Changes

- The SQL adapters now hand back real `Date`s for the timestamps stored inside JSON columns.

  `Identities.ProviderLink.addedAt`, `Sessions.Me.factors[].completedAt` and both dates on `Sessions.Me.actingAs` live inside `jsonb` / `json` / `text` columns. `JSON.stringify` writes a `Date` as an ISO string and the driver hands that string straight back, so on pg, mysql and sqlite all three were typed `Date` but held a `string` at runtime. The memory and Redis stores return real `Date`s, so nothing in the library noticed — it surfaced in caller code as `addedAt.getTime is not a function`, and as `actingAs.expiresAt < Date.now()` comparing a string to a number, which is always `false`: an impersonation window that never looked expired.

  `createSqlStores` revives them at the boundary where bridge rows become library rows, so every dialect is covered at once.

  - An unreadable `addedAt` keeps the link and falls back to the row's `createdAt`. The date is informational, and dropping the entry would silently remove a way into the account.
  - An unreadable `factors[].completedAt` falls back the same way.
  - `actingAs` gets no fallback: a window whose start or end cannot be read is dropped, matching what the Redis session store already did.

  Two new store-compliance tests hold memory, sqlite, pg and mysql to this, rather than only the adapter that happened to be exercised.

  Anyone reading these fields on a SQL adapter was reading a string; on 5.3.6 and earlier the workaround was `new Date(link.addedAt)` at every call site, and those calls keep working unchanged.

## 5.3.6

### Patch Changes

- 80c809a: Deleting an identity now ends every way into it, and a restore no longer resurrects claims the account can no longer prove.

  `flows.signIn` re-reads the identity behind a `startSession` intent, so every sign-in provider was already covered. The credential-first surfaces were not: they resolve a credential row and hand back `row.identityId` without ever looking at the identity.

  - `apiKeys.verify()` refuses a key whose identity has been soft-deleted or erased, reporting `AUTH_APIKEY_INVALID` — the same code as an unknown key, so whether an id still exists is not something an unauthenticated caller can probe. `M2MImpl.exchange()` is covered by the same check; it previously minted a live bearer token for a deleted account. `apiKeyProvider()` wires the identity store in automatically, and the constructor argument is optional so a direct `new ApiKeysFacet(...)` keeps working.
  - `authRefreshoauthToken` accepts an optional `identities` probe and refuses to refresh for a deleted identity. The check runs before the CAS claim and before the provider exchange, so a dead refresh costs nothing and leaves the row intact for a later restore.
  - `softDelete` clears `emailVerified`. The unique indexes are partial on `deletedAt` and `findByEmail` filters the same way, so the address is genuinely free while the row is hidden; restoring must not hand back a verified claim to an address the identity may no longer control.
  - `restore` refuses once the grace window has closed, reporting `AUTH_GRACE_EXPIRED`. The SQL bridges previously cleared `deletedAt` unconditionally, bringing back accounts whose window had long since closed — including ones already queued for hard purge — while the memory adapter refused them. The dialects now agree with the memory adapter.
  - `restore` refuses when the address was claimed while the row was hidden, reporting `AUTH_EMAIL_TAKEN` instead of a raw unique-index driver error on SQL, or two live rows sharing an email on an adapter with no such index.
  - `completePasswordReset` refuses a token whose identity has been deleted, reporting `AUTH_RECOVERY_TOKEN_INVALID` so a reset link cannot double as a way to ask whether an account still exists. It previously rotated the token, wrote the new password and emitted `recovery.password.completed` for an account nobody could sign in to.

  `assertRestorable`, `assertEmailFree` and `profileEmail` are exported from `~/adapters/sql` for bridge authors implementing `restore`.

- 45e1ff6: Every mutating call on the public API now answers with what it did.

  A write that returns `void` cannot be told apart from a write that matched nothing, and forces a second read for information the statement already had. Across the engine's surface, the mutating calls now return the row, the rows, or the count they touched — `null` / `[]` / `0` when nothing matched.

  **Identities.** `softDelete`, `erase`, `link`, `unlink` and `merge` return the row (`restore` already did). Where the dialect has `RETURNING` this is the same round trip; MySQL re-selects by primary key, as it already does for `update` and `restore`. `erase` answers with the row as it was immediately before deletion; `merge` with the survivor, already carrying the union of both provider lists.

  **Sessions.** `revoke` and `revokeByHash` return the session they ended — the row is already read to find it. `revokeAllForIdentity` returns the sessions it ended, so "you were signed out of 4 devices" needs no second query; that list was already read to emit one event per session.

  **Credentials.** The store's `revoke` and `delete` return the row, `deleteByKind` the rows. On top of that, `apiKeys.revoke` answers with the key it revoked, and `mfa.removeTotp` / `removeWebauthnMfa` answer `{ removed }` — the count, not the rows, which carry the shared secret.

  **Orgs.** `removeMember` answers with the membership as it stands left, `setRoles` with the membership carrying its new roles — the _sanitized_ set actually stored, not the one passed in.

  **Flows.** `completeAccountDeletion`, `cancelAccountDeletion`, `completeEmailVerification`, `linkProvider` and `unlinkProvider` carry the identity back as `identity`, alongside the fields they already returned. `completeAccountDeletion`'s `restorableUntil` is now read off the `deletedAt` the store actually wrote rather than a second reading of the clock, so the deadline reported is the one `restore` is measured against.

  **Operations, webhooks, pending, anomaly.** `operations.maintenance` / `readOnly` return the resulting `State`. `webhooks.deliverOne` returns one `Delivery` per eligible endpoint — `{ endpointId, delivered, attempts, lastError? }`. `pending.flush` returns `{ published }` and `discard` `{ discarded }`. `anomaly.unregister` returns whether it removed anything.

  Assertions (`apiKeys.requireScopes`, `operations.assertOperationsForRoute`, `hijack.applyReaction`), registrations (`anomaly.register`, `providers.register`) and `plugins.dispose` stay `void`: they throw or they do not, and a return value would be noise.

  Four silent failures fell out of making the returns honest:

  - `merge` wrote nothing and reported success when the survivor or the dup did not exist. On the SQL dialects it was worse than a no-op: the dup's credentials and sessions were re-pointed at an identity that was not there and the dup was then deleted. The memory adapter had always refused this; every dialect now agrees, and `IdentitiesFacet.merge` checks the survivor before any of it runs, reporting `AUTH_UNAUTHENTICATED`.
  - `flows.completeAccountDeletion` reported `{ identityId, restorableUntil }` for a valid token whose identity had since been erased, promising a grace window over nothing. It now reports `AUTH_RECOVERY_TOKEN_INVALID`.
  - `webhooks.deliverOne` dropped a permanently failed delivery in silence when no dead-letter sink was configured — no log, no return value, nothing to distinguish it from one that landed. This was pinned as a finding; the per-endpoint outcome closes it.
  - `identities.eraseMany`'s loop fallback reports `not-found` for an id that was not there, matching the set-based path, which always did.

  **Breaking for custom adapter authors.** `Identities.Store` and `SqlBridge.Identity` type `softDelete`, `erase`, `link`/`insertProviderLink`, `unlink`/`deleteProviderLink` and `merge` as returning the row or `null`; `Credential.Store` and `SqlBridge.Credential` type `revoke` and `delete` the same way and `deleteByKind` as returning the rows; `Org.Store` types `removeMember` and `setRoles` as returning the membership or `null`. An adapter that returns `void` will not typecheck; return what you touched.

## 5.3.5

### Patch Changes

- 7a1ce88: `AuthEngine.withTransaction(client)` binds the whole public surface - reads included - to a transaction you own, and batch forms report per-row outcomes instead of collapsing to `void`.

  The client is opaque to the library and handed straight back to your adapter, so the engine never learns what driver you use. Nested calls inherit it: `flows.completeAccountDeletion()` reaches `identities.softDelete`, `sessions.revokeAllForIdentity` and `credentials.delete`, and all three land on your transaction. Reads are bound too, so a read inside the transaction sees its own uncommitted writes.

  Events do not fire inside a transaction. They buffer in `pending` and publish on `flush()`, so a rolled-back deletion never appears in the audit trail as a completed one. `discard()` drops the buffer, `peek()` inspects it without draining, and a listener that throws does not stop the drain - every buffered event is attempted and the call rejects with an `AggregateError` at the end.

  Also in this release:

  - `identities` gained `softDeleteMany`, `restoreMany`, `eraseMany`, `updateProfileMany`, `linkMany` and `unlinkMany`; `sessions` gained `revokeAllForIdentities` and `revokeByHashes`; the credential store gained `deleteByIdentities`. Each collapses to one statement per table where the adapter can express it and loops otherwise, so every adapter supports every batch form.
  - A hard failure - a constraint violation, a driver error - throws, which inside your transaction aborts the whole thing and is what makes a batch atomic with your own work. A soft failure - a lost optimistic-lock race, a row that was not there - is reported per row as `stale-write`, `not-found` or `skipped` without throwing.
  - Stores and the drizzle pg, mysql and sqlite bridges declare `withClient`. A store that cannot join a transaction makes `withTransaction` throw `AUTH_MISCONFIGURED` naming that store, rather than silently leaving those writes outside your transaction.
  - Guards - `limiter`, `idempotency`, `hijack` and `anomaly` - are deliberately not reachable on the bound view. An attacker who can force a rollback must not be able to refund the attempts it cost.
  - `createSqlStores` binds optional bridge methods to their bridge instead of destructuring them, so a bridge implemented as a class no longer loses its `this`.

## 5.3.4

### Patch Changes

- 8a13899: Drop `deletedAt` from `authCredentials` and `authSessions`, added in 5.3.3. Both
  tables' `delete()`/`deleteByKind()`/`deleteAllForIdentity()` are hard-delete by
  explicit design (retaining a revoked credential's secret forever, or a dead session
  row, is not a feature), so the column would never have been set by anything in this
  codebase - it was speculative, not wired to a real soft-delete path. `authCredentials`
  already tracks its own dead-state via the adapter-managed `revokedAt`; a second,
  adapter-inert "this row is gone" column duplicated that job without adding one.
  `authIdentities.deletedAt` is unaffected - its `softDelete(id, gracePeriodMs)` is a
  real, adapter-managed flow, unlike these two.

## 5.3.3

### Patch Changes

- fd6e8c2: Round out audit columns on the drizzle schema (pg/mysql/sqlite):

  - `authCredentials`/`authSessions` gain `updatedBy` and `deletedAt` (they already had
    `updatedAt` from a prior release) - both rows are genuinely mutated in place
    (`rotate`/`patchMetadata`/`revoke`, session `update()`), so tracking who/whether
    matters there.
  - `authEvents` drops the `createdBy` it briefly had - it's an append-only audit log,
    never updated, so the only actor-relevant fact is who triggered the event, which
    already lives in the event payload itself.

  Every read method (`findById`, `listByIdentity`, `findByProviderSub`,
  `findByHashedSecret` on credentials; `findByHash`, `listByIdentity` on sessions) now
  filters `deletedAt IS NULL`, matching `authIdentities`. Nothing in this adapter sets
  `deletedAt` on these two tables (`delete()`/`deleteByKind()`/`deleteAllForIdentity()`
  still hard-delete, on purpose - turning them into soft-deletes would mean revoked
  credential secrets are retained forever, which is a regression, not a feature); the
  column is honored if something outside the adapter sets it.

- 30a595d: Fix the vanilla client never sending the CSRF header, so every cookie-authenticated
  write (`signOut` included) failed the server's `verifyCsrf` check. `createAuthClient`
  now reads the CSRF cookie (`__Host-duck-csrf` by default) and echoes it on the
  configured header (`x-csrf-token` by default) for any non-safe method; safe methods
  (`GET`/`HEAD`/`OPTIONS`/`TRACE`) are left alone. Both names are configurable via
  `csrfCookieName`/`csrfHeaderName` on `Cfg`.

  `Provider`'s props and `client/react`'s types also gain the `Profile` generic they
  were missing (`IProviderProps` had no type param, `client` was typed `Client<any>`),
  so a consumer's custom profile type now flows through instead of being erased.

## 5.3.2

### Patch Changes

- 95a4eb2: Add `createdBy`/`updatedBy` columns to the drizzle adapter's tables (`authIdentities`,
  `authCredentials`, `authSessions`, `authEvents`), matching the pattern
  `@gentleduck/iam`'s drizzle schemas already use.

  Nullable, and never set by the adapter itself (it has no actor context) - set them from
  triggers or direct admin writes. `updatedBy` only exists on `authIdentities`, the only
  table with an `updatedAt` column.

## 5.3.1

### Patch Changes

- 959a8a4: Add DB-level defaults for `createdAt`/`updatedAt` on the drizzle adapter's tables
  (`authIdentities`, `authCredentials`, `authSessions`, `authEvents`), matching the
  pattern `@gentleduck/iam`'s drizzle schemas already use.

  The store layer already sets both fields explicitly on every insert and update, so this
  changes no observable behavior through the adapter's own API. It backstops rows written
  outside that path (raw SQL, migrations, manual seeds) so `created_at` is never left null.

- 959a8a4: Add a `valkeyXxx` wrapper next to every Redis-backed store, so switching between
  `redis`/`valkey` clients is a one-line change instead of hand-wiring `valkeyAdapter`
  into each store's config: `valkeySessionImpl`, `valkeyDPoPNonceStore`,
  `valkeyEvents`, `valkeyIdempotency` (`@gentleduck/auth/core/idempotency`), and
  `valkeyLimiter` (new `@gentleduck/auth/limiters/valkey` entry, mirroring
  `limiters/redis`).

  `valkeyEvents` takes a `{ cmd, sub }` connection pair rather than one client: once
  an ioredis/iovalkey connection calls `.subscribe()`, it enters subscriber mode and
  can no longer run ordinary commands (including `PUBLISH`), so the publish/command
  side and the subscribe side need separate connections. `valkeyPubSubAdapter` is
  exported standalone for callers who want to drive `RedisEvents` directly.

  Each `valkeyXxx` factory lives in its own sibling file next to the matching
  `RedisXxx` implementation, mirroring the `redis.ts`/`valkey.ts` split used
  elsewhere: `sessions.redis.ts`/`sessions.valkey.ts`, `dpop-nonce.redis.ts`/
  `dpop-nonce.valkey.ts`, `events.redis.ts`/`events.valkey.ts`,
  `idempotency.redis.ts`/`idempotency.valkey.ts`, and `limiters/redis`/
  `limiters/valkey`. `adapters/valkey` is a re-export barrel, mirroring
  `adapters/redis`. Each also has its own real-server e2e suite colocated next to
  the matching `redis*.e2e.test.ts` (`sessions.valkey.e2e`, `dpop-nonce.valkey.e2e`,
  `events.valkey.e2e`, `idempotency.valkey.e2e`, `valkey-limiter.e2e`).

  Also removes three independent hand-rolled copies of the ioredis-to-`RedisLike`
  translation that predated `valkeyAdapter` (`test/e2e-redis.ts`'s `toRedisLike`, used
  across eleven e2e suites; `events.redis.e2e.test.ts`'s `eventsClient`; and the
  revocation worker's `toEventsClient`), replacing all of them with `valkeyAdapter`/
  `valkeyPubSubAdapter` so there is exactly one implementation of that translation.

## 5.3.0

### Minor Changes

- 39aaa82: Guard every server adapter's routes, and record the caller on the session.

  Elysia, Fastify and Koa ran sign-in, sign-out and provider-begin with no CSRF check,
  while Next, Hono, Express and Nest guarded theirs. Which adapter an application mounted
  decided whether a cookie-authenticated POST could be driven from another origin, and
  nothing in the API hinted at the difference. All seven guard now.

  Every adapter also gets a guard for the application's own routes. `csrfGuard` was
  exported the whole time but no adapter exposed it in its own middleware shape, so
  protecting a route outside the mounted set meant hand-rolling the framework glue:

  - `app.use(expressCsrf(auth))`
  - `app.use(koaCsrf(auth))`
  - `app.use('*', honoCsrf(auth))`
  - `fastify.addHook('preHandler', fastifyCsrf(auth))`
  - `app.onBeforeHandle(elysiaCsrf(auth))`
  - `export const POST = withNextCsrf(auth, handler)`, a wrapper because the App Router
    gives the adapter no chain to hook

  They share `Csrf.GuardOptions`, and each writes its own 403 rather than delegating to an
  error handler the application may not have.

  Sign-in dropped the caller's ip and user-agent in every adapter, so every session row
  recorded a device it could not name and the anomaly detectors had nothing to compare
  against. `callerContext` forwards only what the framework itself resolved: reading a
  forwarded header in the library would take the value the caller wrote, and the host is
  the only layer that knows how many proxies it trusts. Elysia and Hono resolve no address
  themselves, so their context types take an optional `ip` the application sets.

  BREAKING: a cookie-authenticated POST to the elysia, fastify or koa sign-in, sign-out or
  provider-begin route now requires a CSRF token and gets a 403 without one. Bearer and JWT
  transports keep the existing bypass, since they carry auth in the Authorization header
  and are not sent ambiently by a browser.

- 39aaa82: Configure idempotency and anomaly the way the limiter is configured.

  `idempotency` accepted only the facet, so the config line read
  `idempotency: idempotency(memoryIdempotency())` right next to
  `limiter: redisLimiter({ redis, max, windowMs })`. Two spellings for the same idea, and
  the wrapping was easy to forget.

  The key now takes a bare store as well and the engine normalises it, and
  `memoryIdempotency()` / `redisIdempotency()` return a ready facet whose one config
  object carries both store knobs and facet knobs. The whole line is
  `idempotency: redisIdempotency({ prefix: 'auth:idem', redis })`. `new MemoryIdempotency()`
  and `new RedisIdempotency()` still give the bare store, and wrapping an already-wrapped
  facet is a no-op rather than an error.

  `MemoryIdempotency` refused to construct unless `development: true` was passed, in every
  environment rather than only production, which made the no-arg constructor unusable
  including in the engine's own dev fallback. Only `NODE_ENV=production` is refused now,
  and `development: true` is the escape hatch for it.

  `anomaly` had no config key at all: the engine hardcoded `DEFAULT_ANOMALY_CONFIG`, so the
  detectors could be registered but their thresholds and per-signal reactions could never
  be tuned. `anomaly` is merged over the defaults the same way `hijack` is.

  `createAuth` silently dropped two keys its type accepted. `plugins` cannot work because
  installation is async and `createAuth` is not; `oauth.stateSigningSecret` cannot work
  because the secret has to reach each provider at construction. Both now throw
  `AUTH_MISCONFIGURED` naming the call that does work (`await auth.use(plugin)`, and
  `github({ stateSigningSecret })`), rather than booting an engine that quietly lacks what
  was asked for.

- 39aaa82: Record email verification on the column, not the profile.

  `completeEmailVerification` wrote `emailVerified: true` into the identity's profile, and
  the OIDC OP read `email_verified` back out of it for the userinfo claim.

  `updateProfile` merges a caller-supplied patch without filtering keys, so a verified-email
  flag living in the profile is something the account holder can set on themselves, and any
  relying party trusting the `email_verified` claim inherits that. The `emailVerified`
  column has been on the identity row the whole time.

  Both sides read and write the column now, and `beginSignUp` stops seeding the profile
  flag.

  BREAKING: `emailVerified` no longer appears in `identity.profile`. Read
  `identity.emailVerified` instead. Existing rows keep whatever their profile already
  holds; nothing reads it any more. If an application has been trusting
  `profile.emailVerified`, treat that value as unverified user input and reconcile it
  against the column before relying on it.

- 39aaa82: Stamp an audit envelope onto every event that declares one.

  The engine already wrapped its bus in `withAuditStamping`, but the module it comes from
  was never published, so the package did not build from source. It ships now.

  Two sources fill the envelope, in priority order: the ambient one opened by
  `runWithAuditEnvelope()`, which an adapter wraps request handling in once the session is
  resolved, then the emitted session's own `actingAs`. A payload that already carries
  `audit` is left alone. Absent therefore means "no impersonation was in effect", not
  "unknown", but only for events emitted inside a `runWithAuditEnvelope()` scope or
  carrying a session.

  The audited-event list is a total record over `Events.AuditedEvent`, so a new event
  declaring `audit` fails to compile until it is listed, rather than silently going
  unstamped.

  `session.rotated` now carries `previousSessionId`, the hashed id of the session rotated
  away from, present whenever the caller supplied a `previousSid`. Audit consumers use it
  to chain a session's lineage across rotations.

  `authz.revoked` is declared on the event map for the IAM side to publish and duck-auth
  to subscribe to, so every instance can drop cached decisions. It carries no envelope
  precisely because it does not originate here.

  The wrap has to be explicit rather than happening inside `resolveSession`, because doing
  it there needs `AsyncLocalStorage.enterWith`, which segfaults on Bun 1.3.14-canary.

- 39aaa82: Export the factories, and finish the barrels.

  The previous release gave every publicly constructed class a factory function, but
  several were never exported, so `new` remained the only reachable spelling for
  `AnomalyFacet`, `HijackFacet`, `WebhookDeliverer`, `MemoryPasskeyChallengeStore`,
  `AuthMemoryDeviceFingerprintStore`, `DPoPVerifier`, the data-at-rest providers, the
  password hashers, and the api-key / magic-link / passkey / saml / passwords impls.

  The channels barrel exported one type and nothing else, so every channel had to be
  imported by deep path. All six ship from `@gentleduck/auth/channels` now. The anomaly
  barrel likewise omitted both detectors and the fingerprint store, which meant the
  detectors could not be registered without reaching past it.

  On the IAM side, `iamEngine` and `iamLRUCache` are exported alongside their classes.

  BREAKING: three aliases in the `@gentleduck/auth` root now name the factory rather than
  the class, so `new` on them stops compiling.

  - `AuthBackupCodesFacet` is now `backupCodesFacet`; the class is `BackupCodesFacet`.
  - `AuthInMemoryEvents` is now `inMemoryEvents`; the class is `InMemoryEvents`.

  Both classes are exported under their own names, so `new BackupCodesFacet(...)` and
  `new InMemoryEvents()` are the mechanical fix.

- 39aaa82: Make OIDC authorization codes and refresh tokens single-use under concurrency.

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

- 39aaa82: Refuse a session whose identity was erased, on both resolution paths.

  `resolveSession` resolves a request two ways: a transport that can verify a token
  statelessly, else a lookup by sid. Only the sid path refused an erased identity. The
  verify path did the same lookup and returned `{ session, identity: null }`, which is
  truthy, so `makeGuard` passed it and a deleted user was authenticated.

  The check now lives in `finalize`, which both paths already call, so neither can skip it
  and a third added later cannot either. `resolveBySid` keeps its own copy because it is
  exported and callable directly.

  Reaching the weaker path was one line: `jwtTransport` and `dpopTransport` both define
  `verify` and are exported from the same module as `cookieTransport` and
  `bearerTransport`, so adding one to an existing `compositeTransport` array moved every
  request onto it with no other change and no test failing.

  BREAKING: `resolveSession` now throws `AUTH_SESSION_REVOKED` on the verify path where it
  previously returned a result with a null identity. Callers treating a null return as
  "not signed in" will see the error instead, which is what the sid path already did.

  Both paths also agree on a cross-tenant token now. The tenant comparison moved into
  `resolveBySid`, which is the only place it can run before the erased-identity throw, so
  a token for a foreign tenant looks absent on either path whether or not its identity
  still exists, and the identity is never looked up at all.

- 39aaa82: Harden session creation, rotation and expiry.

  `sessions.create` validated that `factors` was an array of at most 16 but never what was
  in it. The Redis reader drops an unlisted method and a non-Date `completedAt` on the way
  back out, so a malformed entry persisted a row that could not be read back intact. Each
  entry is now checked to be `{ method: FactorMethod, completedAt: Date }`. `fingerprint`
  is header-derived like `ip` and `userAgent` and is now capped like them, at 256
  characters.

  `rotateOrCreate` handled `credential-change` after minting the replacement and then
  skipped that row by id while sweeping, which only held because the store had already been
  read. It sweeps the identity first and mints afterwards, so the ordering is not
  load-bearing. The purpose switch gained a `never` default: adding a purpose without
  deciding its revocation semantics is a build error rather than a silent no-op, which is
  how a new purpose would otherwise ship revoking nothing.

  `touch` extended a session's sliding expiry without checking it first, so a session whose
  `expiresAt` had already passed, or was non-finite, was revived by the next request that
  touched it, even though `resolveBySid` would have rejected it. It deletes the row and
  fails closed.

  `session.created` now carries the identity when the caller already holds it (sign-in,
  sign-up, impersonation), so a listener does not have to re-read the row it was just
  handed. `createGuest` and `promoteGuest` return the csrf token they were already minting,
  and `promoteGuest` forwards `fingerprint` and `actingAs`, so guest device-binding
  survives promotion.

  BREAKING: `sessions.create` throws `AUTH_MISCONFIGURED` on a malformed factor entry it
  used to persist. Callers building factors by hand should confirm `completedAt` is a
  `Date` and not an ISO string.

- 39aaa82: Make a TOTP code single-use within its validity window.

  `verifyTotp` answered only yes or no, which is not enough to satisfy NIST SP 800-63B's
  requirement that a verifier accept a given OTP once per validity period. The drift window
  spans three steps, so a code observed once, over the user's shoulder or in a phished
  prompt, stayed valid for about ninety seconds. That window is the whole protection on a
  privileged step-up.

  `matchTotpStep` returns which time step matched, scanning the full window without
  short-circuiting for the same reason `verifyTotp` does: stopping early leaks which step
  matched. The step is recorded on the enrollment as `lastTotpStep`, and a code matching
  that step or an earlier one is refused as a replay.

  Confirmation spends its code too, so the code that enrolls a factor cannot immediately be
  replayed into a step-up on the enrollment it just created.

  One consequence worth knowing: a user who legitimately needs two step-ups inside the same
  30-second step must wait for the next code. That is the intended reading of the
  requirement.

### Patch Changes

- 39aaa82: Fix three defects in the drizzle bridges.

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

- 39aaa82: Roll back a plugin install that fails.

  `use()` claimed the plugin id first, then subscribed its event handlers, exposed its
  facet and awaited `install`. A throw from any of those left the id claimed, the handlers
  subscribed and the facet reachable, so retrying under the same id hit "already installed"
  while the half-wired plugin kept receiving events.

  Providers register first, before the id is committed, so a duplicate provider id throws
  where the author can fix the collision and reinstall under the same id. Everything after
  that is undone on a throw, and the id is committed last.

  `Providers` has no unregister, so a provider registered by a plugin that fails later
  stays registered. That limit is named in the code rather than papered over.

- Make the not-blank check constraints reject whitespace.

  `length(trim(x)) > 0` only strips ordinary spaces, so a name, subject id, scope or
  credential secret consisting of a tab, a newline or a form feed passed the check that
  exists to refuse exactly that. Seven constraints were affected:
  `auth_credentials.secret`, `iam_assignments.subject_id` and `.scope`, `iam_policies.name`,
  `iam_roles.name` and `.scope`, `iam_subject_attrs.subject_id`.

  Each dialect gets the strongest form it has. Postgres and MySQL match a non-whitespace
  character (`~ '[^[:space:]]'` and `REGEXP '[^[:space:]]'`); SQLite has no regexp operator
  built in, so it trims the whitespace set explicitly and compares against the empty string.
  All three were verified against a real server for a tab, a newline, a carriage return, a
  vertical tab, a form feed and a plain space.

  Existing databases need a migration: drop each constraint and add it back in the new form.
  Any row already holding a whitespace-only value has to be repaired first, or the
  `ALTER TABLE` is refused.

## 5.2.0

### Minor Changes

- Export the idempotency and events modules, and stop callers casting the drizzle bridge.

  - `./core/idempotency` is a new subpath export. `RedisIdempotency` and
    `IdempotencyImpl` were reachable only through the bundle before, so an
    application wiring a production idempotency store had to cast into
    `ConstructorParameters<typeof AuthEngine>[0]['idempotency']`.
  - `./core/events` is a new subpath export, and `./core` now re-exports the
    `Events` type namespace and `RedisEvents`. Subscribing to the bus to persist an
    audit trail was not expressible without it: the engine defaults to an in-memory
    bus, so nothing reaches an `auth_events` table unless the application listens.
  - `createDrizzlePgBridge`, `createDrizzleMysqlBridge` and
    `createDrizzleSqliteBridge` are now generic over the profile, matching
    `createSqlStores`. They returned the base profile shape, so every caller with
    its own profile had to cast the whole bridge. The widening now happens once
    inside each adapter.
  - `findByEmail` is case-insensitive in all three drizzle adapters. The uniqueness
    constraint is `unique (lower(profile->>'email'))` but the lookup compared
    exactly, so an identity registered as `Ada@example.com` could never sign in
    again: signup stores the address verbatim and the lookup never found it.

## 5.1.0

### Minor Changes

- bc8a9ea: Prefix the drizzle store table exports with `auth`, add keyed JWT transport
  configuration with rotation support, and refuse the in-memory idempotency store
  outside development.

  **Renamed drizzle table exports** across `mysql`, `pg` and `sqlite`:

  - `credentialsTable` is now `authCredentials`
  - `identitiesTable` is now `authIdentities`
  - `sessionsTable` is now `authSessions`
  - `eventsTable` is now `authEvents`

  The old names are gone, so update imports from
  `@gentleduck/auth/adapters/drizzle/{mysql,pg,sqlite}`. Only the exported
  bindings change — the physical table names are untouched, so no database
  migration is required.

  **Keyed JWT transport.** `jwtTransport` config is now a `JwtTransport` namespace
  taking an explicit `signKey` plus the set of currently-valid `verifyKeys`, each
  with a `kid` and per-key `alg` (HS256 by default, ES256 and RS256 via a PEM
  private key). Keeping superseded keys in `verifyKeys` for an overlap window lets
  already-issued tokens keep verifying through a rotation instead of failing at
  cutover.

  **`memoryIdempotency()` now throws** unless constructed with
  `{ development: true }`, and always throws when `NODE_ENV` is `production`. Its
  state is per-process, so it stops deduplicating as soon as a second instance
  runs; it now fails loudly instead of degrading silently behind a load balancer.

  The `@gentleduck/iam` peer range widens from an exact pin to `^`, so a minor iam
  release no longer takes this package out of range.

## 5.0.0

### Minor Changes

- Restructure core into `engine/` and `config/` subfolders matching duck-iam patterns. Rename `defineAuth` → `createAuth` as primary entry point. Extract `AuthEngineTypes` and `AuthDefine` into dedicated types files. Add `Auth` prefix to all public classes.

### Patch Changes

- Updated dependencies
  - @gentleduck/iam@5.1.0

## 4.0.1

### Patch Changes

- fix: strip redundant iam/auth prefixes from public exports
- Updated dependencies
  - @gentleduck/iam@5.0.1

## 4.0.0

### Major Changes

- Prefix all public exports with package namespace (`Auth*`/`Iam*`/`IAM_*`/`AUTH/*`) so the origin is clear at the type level when both packages are imported together. This is a breaking change — all consumers must update import references to the new names.

### Patch Changes

- Updated dependencies
  - @gentleduck/iam@5.0.0

All notable changes to `@gentleduck/auth` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (v0.2 plan items)

- **WebAuthn-MFA factor.** Six new methods on `MfaFacet`:
  `beginWebauthnMfaEnrollment`, `confirmWebauthnMfaEnrollment`,
  `beginWebauthnMfaVerify`, `verifyWebauthnMfa`, `hasWebauthnMfa`,
  `removeWebauthnMfa`. Lazy-loads `@simplewebauthn/server`. Counter-
  rollback rejection emits `suspicious` events with signal
  `webauthn-mfa-counter-rollback`. New `'webauthn-mfa'` Credential kind.
  (`core/facets/mfa.ts`, `core/types/credential.ts`)
- **KMS-envelope `DataAtRest.IAdapter` (`KmsEnvelopeDataAtRest`)**
  driven by a vendor-agnostic `Kms.IProvider` contract. Reference
  `AwsKmsProvider` that lazy-loads `@aws-sdk/client-kms`. Encryption
  context binds wrapped DEKs to `(identityId, field)` so a leaked
  ciphertext can't unwrap DEKs from other rows. New subpath export
  `@gentleduck/AUTH/core/dataAtRest`. (DESIGN §1, §C5)
- **JwtTransport: EdDSA + live JWKS rotation.** Adds `'EdDSA'`
  (Ed25519) to the alg union with native node:crypto support. New
  `rotateSignKey({ signKey, verifyKey? })` and
  `retireVerifyKey(kid)` methods promote a new signing key and
  retire the old one without recreating the transport instance; the
  old kid stays in the verify ring during the overlap window so
  already-issued tokens keep verifying. (DESIGN §3, §23 Q2)
- **`Credential.IStore.patchMetadata(id, patch, ctx)`.** Shallow
  merge into a credential's `metadata` and bump `version` in one
  step; either server-composed (SQL `jsonb || $patch`) or
  read-modify-write inside a transaction. Used by
  `MfaFacet.confirmTotpEnrollment` for an atomic confirm (replaces
  the prior delete+upsert race) and by passkey verify to advance
  the WebAuthn signCount on each assertion. Covered by the adapter
  compliance harness so every store implementation enforces the
  contract. (`core/types/credential.ts`,
  `adapters/{memory,sql}/index.ts`, `adapters/__compliance__/index.ts`)
- **AAL=3 detection on hardware-bound passkeys.** `MfaFacet.eligibleAal`
  now returns `3` when the identity has a passkey credential whose
  enrollment metadata indicates `deviceType === 'singleDevice'` AND
  `backedUp === false` - matching NIST 800-63B hardware-binding.
  Cloud-synced passkeys (iCloud Keychain / Google Password Manager)
  stay at AAL=2. (`core/facets/mfa.ts`)
- **Vue / Svelte / Solid clients.** Three new framework adapters
  wrapping the vanilla AuthClient, each as an optional peerDep:
  - `@gentleduck/AUTH/client/vue` - `createAuthVuePlugin` +
    `useSession`/`useSignIn`/`useSignOut` composables. Vue is
    resolved at runtime via `require('vue')` so the auth core has
    no Vue in its module graph.
  - `@gentleduck/AUTH/client/svelte` - `createAuthStore` returning
    a duck-typed Svelte-store contract; no Svelte import needed at
    typecheck time.
  - `@gentleduck/AUTH/client/solid` - `AuthProvider` + Solid
    signals; uses real `solid-js` types.

### Security

> Five rounds of focused security review against the auth-critical
> surface. 42 fixes shipped; each is covered by a regression test
> (600 -> 683 vitest tests over the five rounds).

**Round 5 (AuthRoot wiring / sessions matrix / anomaly detectors):**

- **P0:** `AuthRoot.resolveSession(req, { expectedTenantId })` now
  refuses a session whose `tenantId` differs from the request's
  expected tenant. Without this, a SID/JWT minted under tenant A
  presented at a tenant-B endpoint returned tenant-A's identity.
  (`core/auth.ts`)
- **P0:** `FlowsFacet.completeSignUp` now routes through
  `SessionsFacet.rotateOrCreate({ purpose: 'guest-promotion',
previousSid })` so the prior guest SID is revoked atomically with
  the new user SID. DESIGN §37 mandated this; the prior `create()`
  call bypassed the fixation guarantee. New optional `previousSid` arg.
  (`core/facets/flows.ts`)
- **P0:** End-to-end CSRF auto-enforcement on every server adapter
  (express / hono / next). `SessionsFacet.create` returns a
  plaintext `csrfToken`; `CookieTransport.issue` emits the
  `__Host-duck-csrf` cookie when supplied; mounted signin / signout /
  provider-begin routes call `csrfGuard(auth, req)` first.
  Double-submit (Layer-2) is correctly skipped when no session
  exists yet (signin / signup-begin), so Layer-1 (Sec-Fetch-Site)
  alone protects the unauthenticated state-changes.
  (`core/csrf.ts`, `core/transport/cookie.ts`, `core/facets/sessions.ts`,
  `server/{express,hono,next}/index.ts`)
- **P1:** `AuthRoot.strict({ env: 'production' })` now catches an
  explicitly-passed `NoopLimiter` (via `__isNoopLimiter` brand) and
  walks ALL three stores (identities + sessions + credentials) for
  the memory-adapter heuristic. Closes "mixed adapter" misconfigs
  where memory sessions slipped past the production check.
  (`core/auth.ts`)
- **P1:** `impossibleTravelDetector` no longer no-ops when lat or
  lon is `0` (Equator / Prime Meridian) and rejects negative
  elapsed-ms (clock-skew or attacker-planted lastSeen) before the
  speed calc. Pathological `maxKmPerHour` (zero, negative,
  non-finite) throws at construction. (`core/anomaly/impossible-travel.ts`)
- **P1:** `deviceFingerprintDetector` IPv6 subnet now expands
  compressed addresses (`::1`, `2001:db8::1`) before taking the /48
  prefix. Previous naive `split(':').slice(0,3)` collapsed unrelated
  networks to the same subnet key, suppressing `new-device` MFA
  prompts. (`core/anomaly/device-fingerprint.ts`)

**Round 4 (MFA / dataAtRest / identities / cookie):**

- **P0:** `BackupCodesFacet.generate` no longer uses `Math.random()` to
  top off codes or modulo-bias the base64url input over the readable
  alphabet. New `generateBackupCode` draws every character from
  `crypto.randomBytes` with rejection sampling against the upper
  modulo-bias tail. Restores the nominal `32^8 ~ 40 bits` entropy
  (previous implementation was effectively ~30 bits).
  (`core/mfa/backup-codes.ts`)
- **P1:** `BackupCodesFacet.verify` uses `timingSafeEqual` on the
  per-code hash and drives the credentials loop to completion so
  early-exit timing cannot leak match position. Successful consumption
  now soft-revokes (`revoke()`) rather than hard-deletes the row, so
  a subsequent replay attempt surfaces against an already-revoked
  audit trail instead of a phantom code.
  (`core/mfa/backup-codes.ts`)
- **P1:** `RememberMeFacet.revoke(identityId, credentialId)` now
  requires identity ownership and refuses to delete rows that belong
  to a different identity. Without this, a consumer surfacing `revoke`
  to an HTTP route that takes `?credentialId=` would let any
  authenticated user revoke any other user's trusted-device row.
  (`core/mfa/remember-me.ts`)
- **P1:** `IdentitiesFacet.getByEmail` (and `bulkCreate` lookup) now
  `email.trim().toLowerCase()` the input. Without normalization,
  `Bob@x.com` and `bob@x.com` created duplicate identities, password
  resets went to only one, and case variants leaked via differential
  responses. (`core/facets/identities.ts`)
- **P2:** `AesGcmDataAtRest` accepts `previousKeys` so ciphertexts
  written under a rotated kid can still be decrypted. Previously the
  `kid` was parsed from the ciphertext but discarded - every key
  rotation stranded existing data with silent auth-tag mismatch.
  Duplicate kids across `(current, previousKeys)` throw at
  construction. (`core/dataAtRest/aes-gcm.ts`)
- **P2:** `CookieTransport` constructor enforces all three `__Host-`
  prefix invariants: no `Domain`, `Path=/`, and `Secure=true`.
  Browsers silently drop cookies that violate them - fail-fast
  catches the misconfig in CI rather than at runtime as "session
  never sticks". (`core/transport/cookie.ts`)
- **Carry-over P2 (Round 3):** Magic-link `_send` no longer forwards
  the channel adapter's `error.message` to the caller (would reflect
  token plaintext on SMTP/SES errors). (`providers/magic-link/index.ts`)
- **Carry-over P2 (Round 3):** Webhook signatures bind the timestamp
  (`X-Duck-Timestamp` header), constructor SSRF-guards endpoint URLs
  against loopback / private / link-local / cloud-metadata hosts.
  (`core/webhooks/index.ts`)

> Three prior rounds (JWT, DPoP, FlowsFacet, OAuth refresh,
> IdempotencyFacet, M2M, Hijack, OIDC, SQL examples, passkey
> WebAuthn, CSRF, compliance presets) detailed below.

**Round 3 (passkey / magic-link / CSRF / webhooks / compliance):**

- **P1:** Passkey counter-rollback detection - previously dead code
  (`newCounter` was read then `void`-discarded). Now rejects on
  `newCounter !== 0 && newCounter <= stored`, emits a
  `passkey-counter-rollback` suspicious event, and advances the
  stored baseline via `Credential.IStore.patchMetadata` so the
  baseline tracks the authenticator across assertions (closes the
  earlier "needs metadata-update method" gap).
  (`providers/passkey/index.ts`)
- **P1:** Passkey `complete` now binds the credential to (a) the
  caller-supplied `email` hint by asserting
  `cred.identityId === findIdentityByEmail(email).id`, and (b) the
  WebAuthn `response.userHandle` bytes. Previously the email was a UI
  hint only and the userHandle was ignored - letting an attacker who
  possessed any valid passkey and knew a victim's credential ID (not a
  secret) sign in as the victim. (`providers/passkey/index.ts`)
- **P1:** Passkey registration now hashes the identityId to a stable
  32-byte WebAuthn `user.id` via sha-256 instead of `TextEncoder`.
  Browsers silently truncate user.id at 64 bytes; long composite IDs
  (ULIDs, `tenant:user` namespaces) collided on the authenticator and
  surfaced the wrong identity on discoverable-credential sign-in.
  (`providers/passkey/index.ts`)
- **P2:** Webhook signatures now bind the timestamp:
  `signWebhookBody(secret, body, timestamp)` HMACs `${ts}.${body}` and
  the deliverer emits `X-Duck-Timestamp`. `verifyWebhookSignature`
  takes `{ timestamp, toleranceMs }` and rejects replays outside the
  window (default 5 min). (`core/webhooks/index.ts`)
- **P2:** Webhook constructor now SSRF-guards endpoint URLs. Refuses
  non-HTTPS by default (escape hatch `allowInsecure: true`), refuses
  loopback / private / link-local / cloud-metadata hosts even with
  `allowInsecure`. Closes the metadata-server exfil vector for any
  deployment that populates the endpoint list from tenant input.
  (`core/webhooks/index.ts`)
- **P2:** Magic-link `_send` no longer forwards the channel adapter's
  `error.message` to the caller. SMTP / SES error objects commonly
  embed the rendered message body - which for magic-link is the
  plaintext token URL - into their error metadata. Previously
  surfacing it via `AUTH/PROVIDER_FAILED.detail` broke the single-use
  invariant by reflecting the token in the HTTP response + any error
  sink. (`providers/magic-link/index.ts`)
- **P2:** CSRF `origin-only` mode now refuses `Sec-Fetch-Site: none`
  when no Origin allowlist is configured. Direct user-navigation POSTs
  - spoofable non-HTTP contexts both surface as `none` - gating on
    Origin was the only Layer-1 defense and the prior code fell open
    when the allowlist was empty. (`core/csrf.ts`)
- **P2:** `applyCompliancePreset` brands the returned config with a
  non-enumerable `__compliancePreset` marker so `AuthRoot.strict()`
  can detect the preset and auto-call `assertComplianceStrict`.
  Previously, `applyCompliancePreset` ratcheted only the numeric knobs
  (password length, session TTLs) - `minAal`, `requireDataAtRest`,
  `requiredStrictChecks` silently dropped unless the operator
  remembered to call `assertComplianceStrict` by hand. New
  `readCompliancePreset` helper exposes the marker. (`core/compliance.ts`)
- **P2:** `ApiKeysFacet.verify` runs a synthetic sha256 + store
  lookup on the prefix-mismatch path so timing signature matches the
  success path. Closes a timing oracle that distinguished valid-format
  junk from "live api-key wrong secret". (`core/facets/apikeys.ts`)

**Round 2 (M2M / Hijack / OIDC / adapter consistency):**

**Round 2 (M2M / Hijack / OIDC / adapter consistency):**

- **P0:** `M2MFacet.exchange` now signs the granted scopes into the
  JWT via a new `Transport.IssueOpts.scope` + `JwtPayload.scope`. The
  `scopeMode: 'intersect'` / `'strict'` mechanism is now enforced on
  the wire - resource servers branch on `payload.scope`. Previously
  the granted set lived only in the envelope and was dropped on
  serialization. (`core/facets/m2m.ts`, `core/transport/jwt.ts`,
  `core/types/transport.ts`)
- **P1:** `HijackFacet.evaluate` evaluates BOTH IP and UA branches and
  picks the strongest reaction (precedence: revoke > mfa > rotate >
  ignore). Prior implementation returned on the first non-ignore
  branch, silently downgrading the UA reaction. Also: one-sided
  fingerprint absence is now treated as drift (downgraded to rotate)
  so a request stripping the User-Agent header doesn't bypass
  detection. (`core/facets/hijack.ts`)
- **P1:** `M2MFacet` now refuses to mint a token when the
  caller-supplied `tenantId` disagrees with the credential's own
  tenant; falls back to the credential's tenantId when the caller
  omits it. `ApiKeysFacet.verify` returns the row's tenantId.
  (`core/facets/apikeys.ts`, `core/facets/m2m.ts`)
- **P1:** `ApiKeysFacet.verify` runs a synthetic sha256 + store
  lookup on the prefix-mismatch path so the timing signature matches
  the success path. Closes a timing oracle that distinguished
  "live api-key format" from "junk". (`core/facets/apikeys.ts`)
- **P2:** `buildOidcDiscovery` parses + canonicalizes the issuer via
  `new URL()`, refuses non-HTTPS in production (escape hatch
  `allowHttp: true`), spreads `extraClaims` BEFORE canonical fields so
  the extension hatch cannot shadow `issuer`/`jwks_uri`/etc., and drops
  `'none'` from `token_endpoint_auth_methods_supported` by default.
  (`oidc/index.ts`)
- **P2:** Drizzle adapter examples - pg/mysql/sqlite `findByEmail` and
  `findByProviderSub` aligned with `findById`'s null-tenant semantics
  (null-tenant rows are "global identities" reachable from any tenant).
  Previously inconsistent - surfaceable as duplicate identity creation
  on next OAuth callback.
  (`adapters/sql/examples/drizzle-{pg,mysql,sqlite}.example.ts`)
- **Docs:** M2MFacet class JSDoc now explicitly notes that revocation
  is lazy (JWT lives until `exp` regardless of api-key revocation) so
  operators don't assume "revoke == kill". (`core/facets/m2m.ts`)

**Round 1 (JWT / DPoP / FlowsFacet / OAuth refresh / IdempotencyFacet):**

- **P0:** `completePasswordReset` now requires `metadata.kind ===
'password-reset'`. The `kind: 'recovery'` credential row is shared by
  password-reset, email-verification, account-deletion, and
  signup-flow tokens. Without this assertion, an attacker holding any
  recovery-kind token (e.g. an email-verification link) could call
  `completePasswordReset` and set the victim's password.
  (`core/facets/flows.ts`)
- **P1:** `resolveBySid` + `JwtTransport.verify` now enforce
  `actingAs.expiresAt`. The 1-hour cap on impersonation was previously
  informational only - sessions stayed live for the full session TTL
  (default 7d). (`core/facets/sessions.ts`, `core/transport/jwt.ts`)
- **P1:** `JwtTransport.verify` now reconstructs `session.fresh` from a
  new `frsh` claim (rotatedAt epoch) instead of hard-coding `true`. The
  freshness gate that protects `completePasswordReset` / `checkStepUp`
  in cookie mode now applies identically in JWT mode. New
  `JwtTransport.IConfig.freshnessMs` knob (default 5min) matches the
  cookie-session default. (`core/transport/jwt.ts`)
- **P1:** OAuth refresh-token rotation closes the TOCTOU race between
  `findByHashedSecret` and `revoke + upsert`. The row is claimed via
  `Credential.rotate(id, sameSecret, expectedVersion)` (CAS on
  version) before the IdP exchange runs; concurrent refreshes get
  AUTH/STALE_WRITE on the second rotate and revoke the family per RFC
  6749 §10.4. (`providers/oAUTH/core/refresh.ts`)
- **P1:** `IdempotencyFacet.handle` no longer double-executes when a
  worker loses the `claim()` race. Both the in-memory and Redis stores
  filter the claim tombstone, and the facet polls (bounded exponential
  backoff, default 5s) until the originator's `put()` lands -
  returning a 409 if the originator crashed without writing.
  (`core/facets/idempotency.ts`)
- **P2:** `AnomalyFacet.decide()` now fails CLOSED on non-finite signal
  scores. A buggy detector emitting `NaN` previously sank into
  `'allow'` via comparison short-circuits.
  (`core/facets/anomaly.ts`)
- **P2:** `IdempotencyFacet.handle` now takes an optional `identityId`
  and scopes the cache key by it. A cached response minted for Alice
  can no longer be served to Bob under the same tenant + key. For
  anonymous routes the scope falls back to `_anon` (callers should
  fingerprint by IP+UA upstream). (`core/facets/idempotency.ts`)
- **P2:** `JwtTransport` constructor rejects duplicate-kid entries in
  `verifyKeys` (silent last-wins) and rejects `signKey` whose alg/key
  mismatches a verifyKey under the same kid. HS256 enforces key
  equality; asymmetric algs only enforce alg parity (verifyKey holds
  the public counterpart of signKey's private material).
  (`core/transport/jwt.ts`)
- **P2:** `DPoPVerifier.verify` now rejects authed-request proofs
  whose `ath` claim is missing (RFC 9449 §4.3) AND rejects proofs
  carrying `ath` when no access token is supplied to verify against.
  (`core/transport/dpop.ts`)
- **P2:** `DPoPVerifier` accepts an optional `expectedNonce`
  (string or thunk) per RFC 9449 §8/9. Lets multi-pod deployments
  tighten the replay window beyond the local jti store via a rotating
  server-issued nonce. (`core/transport/dpop.ts`)
- **P2:** OAuth refresh now emits a `suspicious` event with signal
  `oauth-refresh-unknown-row` when `findByHashedSecret` returns null.
  Replay of a hard-deleted (post-GC) row token surfaces as a leak
  signal operators can route to oncall, even though the familyId is
  no longer available to auto-revoke.
  (`providers/oAUTH/core/refresh.ts`)

### Added

- Namespace migration: every public exported type lives inside its owner
  namespace (`SessionsFacet.IConfig`, `Captcha.IVerifier`, `Identity.IIdentity`).
  `scripts/audit-namespaces.ts` enforces the convention.
  `scripts/inline-types-into-namespace.ts` automates the migration.
- CLI: `migrate <pg|mysql|sqlite>` emits CREATE TABLE DDL matching the
  `SqlBridge` row contract. Tenant + composite indexes included.
- CLI: `keys rotate hs256` mints a new HS256 secret + rollover snippet
  that keeps the previous kid on `verifyKeys` for in-flight JWTs.
  Default `--new-kid` includes a random suffix to prevent collisions on
  sub-second rotation.
- CLI: `emit-openapi` dynamic-imports the local `auth.ts` and prints the
  OpenAPI 3.1 spec (or writes via `--out=<path>`).
- `@gentleduck/AUTH/test`: `createTestAuth()` helper that builds an
  `AuthRoot` wired to in-memory adapters with a `TestAuth.IOverrides`
  shape for surgical swaps in test code.
- `AnomalyFacet.decide()` + `IDecision` type: `'allow' | 'step-up' | 'deny'`
  recommendation per signal set. `IConfig.reactions` map for per-kind
  overrides. `unregister(id)` complements `register()`.
- `AnomalyFacet`: NaN / non-finite scores from a buggy detector fail
  CLOSED (`'deny'`), not silently allow.
- `adapters/sql/examples/`: parallel Drizzle reference implementations
  for MySQL and SQLite alongside the existing pg example.
- `SECURITY.md`: dedicated security policy + Deployment Hardening Guide
  (15 items covering transport, JWT rotation, DPoP, rate limiting,
  idempotency, password hashing, magic-link channels, OAuth reuse
  detection, CSRF, MFA step-up freshness, impersonation, anomaly
  detectors, PII redaction).

### Changed

- `AnomalyFacet` constructor accepts `Partial<IConfig>` and merges with
  `DEFAULT_ANOMALY_CONFIG` so consumers can supply just the field they
  want to tweak.
- `cli migrate mysql` emits `VARCHAR(64)` for primary-key + index columns
  (MySQL refuses `TEXT PRIMARY KEY` with ERROR 1170). Same dialect emits
  `CREATE INDEX` without the `IF NOT EXISTS` guard (unsupported pre-8.0.29).
- `cli migrate` and `cli emit-openapi` `--out=<path>` flag is path-contained
  to the current working directory (refuses `../../...` traversal).
- Drizzle reference examples (pg / mysql / sqlite): `merge()`,
  `insertProviderLink()`, `deleteProviderLink()` are now tenant-scoped.
  Schemas now declare the `(kind, secret)` composite index plus
  `expires_at` / `absolute_expires_at` session indexes that the bridge
  contract documents but had been omitted.
- Drizzle mysql + sqlite examples: `listByIdentity` uses `!== undefined`
  for the tenant filter so empty-string tenant ids don't silently drop
  the predicate. sqlite `findByProviderSub` matches links whose stored
  `providerSub` is null when the lookup sub is null.

### Documentation

- `STATUS.md` refreshed: 617 -> 626 -> 632 tests passing across 68 files;
  v0.1 coverage updated from ~80% to ~98% of v1.0 MUST surface; tooling
  list updated to mention the audit + inline scripts.
- `DESIGN.md` `[pending v0.2]` markers removed from sections that have
  shipped (passkey, observability, OpenAPI, i18n, CLI, test helpers).
  §22 v1.0.0 scope rewritten to reflect actual shipped vs. follow-on.
  §23 open-questions split into "closed" (WebAuthn library, DPoP,
  attestation policy) vs. "still open" (tenant resolution, jose
  migration, GeoIP source, OIDC cache, federation conflict UX, native
  SDKs).
- `README.md` surface tables synced: 6 OAuth providers, passkey
  discoverable+username, SAML, SQL bridge + Drizzle reference impls,
  6 channels, 9 server adapters, OIDC + OTel + i18n + test helper
  subpath exports listed. Status table reflects v0.1 reality.

### Removed

- `scripts/add-namespaces.ts` and `scripts/add-namespaces-v2.ts`
  (superseded by `audit-namespaces.ts` + `inline-types-into-namespace.ts`).

## [0.1.0] - prior to this changelog

Initial pre-publish surface. Faceted `AuthRoot` with 14 facets, 4
transports, memory + redis + sql-bridge adapters, 11 providers,
9 server adapters, 2 clients, 6 channels, CLI, OpenAPI generator, OIDC
discovery, OpenTelemetry instrumentation, i18n catalog, adapter compliance
harness, bundle benchmark, threat model. See `STATUS.md` for the full
shipped surface.

[Unreleased]: https://github.com/gentleeduck/duck-iam/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gentleeduck/duck-iam/releases/tag/duck-auth-v0.1.0
