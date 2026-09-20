---
'@gentleduck/auth': minor
---

Expose `updatedAt` on the session, credential and api-key surfaces.

Every SQL dialect already carried an `updated_at` column, maintained by drizzle's `$onUpdate`, and every
dialect then projected it back out of the row before a caller could see it. `Identities.Me` exposed its
own; `Sessions.Me` and `Credential.Me` did not, so there was no way to ask when a session or a credential
was last written.

- `Sessions.Me.updatedAt` and `Credential.Me.updatedAt` are now part of the row, and so is
  `Credential.Public`, which is `Me` minus the secret.
- `ApiKeys.ApiKey.updatedAt` comes through the projection over the backing credential row.
- The OpenAPI `Session` schema declares it, so generated clients type it.
- The memory and redis stores stamp it on every write, matching what `$onUpdate` does in SQL. A caller
  cannot set it through a patch: it tracks the write, and is not backdatable.
- A redis session written before this release has no `updatedAt` field. It reads back as its `createdAt`
  rather than being refused, so an upgrade does not sign existing sessions out.

The store-compliance suite now asserts, on all six backends, both that the field is present and typed and
that every write actually moves it — an exposed timestamp that never changes would be worse than no
timestamp at all.

Implementors of a custom `Sessions.Store` or `Credential.Store` must return `updatedAt` on the rows they
answer, and `Sessions.CreateInput` now carries it; the engine supplies it at create.

Stop sending the session's CSRF hash to the browser.

`GET /session` answered `JSON.stringify(resolved.session)`, and the row carries `csrfHash`. All seven HTTP
adapters did it, so the per-session hash reached every client that asked who it was, for a field no client
has a use for: the browser echoes the plaintext from its `__Host-` cookie, and the comparison is
server-side. `Identities.exportAll` had always stripped the field, so the package's own intent was clear
and the route was the one place contradicting it.

- The handlers strip it inline, so the wire now carries the row minus that one field.
- `Sessions.Public` names that shape, and `VanillaClient.SessionResult.session` plus `reviveSession` are
  typed to it rather than to `Sessions.Me`. A caller reading `session.csrfHash` off a client result now
  fails to compile, which is the point.
- Two guards, both mutation-checked: a static-analysis test that scans every `server/*/index.ts` from the
  directory rather than a list, so a new adapter is covered the day it lands, and a live assertion on the
  hono route's response body.

Answer the facts the API already held but did not hand back.

- The OpenAPI `Session` schema declared 12 of the row's fields. `ip`, `userAgent`, `fingerprint` and
  `actingAs` are on the wire and non-secret, so a generated client was typed narrower than its own
  responses. They are declared now; `csrfHash` stays out, deliberately.
- `ApiKeys.create` accepts a `tenantId` and `exchange` reports one, but `ApiKeys.ApiKey` dropped it, so a
  key could be scoped to a tenant and never read back. It is now on the record, absent when unscoped.

Still deliberately hidden: `Credential.secret`, `Sessions.Me.csrfHash` outside the server, and mysql's
generated `passwordKey`/`emailNorm`/`usernameNorm`, which are index carriers rather than fields.

Mark auth responses uncacheable.

Nothing in the package set `Cache-Control` — not on a route, not in a shared helper, and not as advice in
the docs. `GET /session` is the sharp end: one URL for every caller, a body that differs by cookie, and no
`Vary`. A CDN or proxy caching it hands one caller another's identity and session. The same applied to the
magic-link and OAuth callback GETs, whose URLs carry a one-time token and an authorization code.

Every HTTP adapter now sets `cache-control: no-store` on the responses it builds, including error and
redirect paths. grpc is exempt: it is not HTTP. A static-analysis test enforces it per adapter, derived
from the directory rather than a list, and the hono session route asserts the header on a live response.

Close the timing oracle on the magic-link request.

`requestPasswordReset` is careful about this: both branches mint and hash a token and make the same store
calls in the same order, because "response time answers what the response body refuses to". `magicLink.begin`
implements the same contract and did the opposite — an unknown address returned before the token mint and
before the credential insert, so it was measurably the faster one, and the endpoint told a caller whether an
address had an account. Its comment claimed the branches matched; only the channel dispatch did.

- The unknown branch now mints and hashes a token like the known one, and answers the write with a read of
  the same table under the same tenant scope. A decoy write is not possible: `auth_credentials.identity_id`
  is a foreign key, which is the reason the reset flow reads there too.
- `autoCreateIdentity` and `autoCreateProfile` behave as before; only the early returns are gone.

The existing `magic-link-timing-defense.test.ts` passed throughout, both before and after. It compared
wall-clock across the two branches with a 50 ms tolerance, against the memory adapter, where the skipped
insert costs microseconds — it could only ever prove that neither branch blocks on the channel. It now also
counts the store round trips each branch makes and requires them to line up, which is the assertion that
fails on the old code: the unknown branch made none where the known one made two.

CSRF-guard the passkey routes, and bound `passkey.begin`.

`mountHono` mounts `passkey/begin` and `passkey/complete` as POSTs. Neither called `csrfGuard`, while
`/signin`, `/providers/:id/begin` and all five MFA routes in the same file do — and `passkey/complete` is
a sign-in, the same thing `/signin` is. There was no note anywhere saying the omission was meant. Both are
guarded now, and a new test walks the routes `mountHono` actually registers and requires every POST among
them to refuse a cross-site request, so a route mounted without the guard fails the day it lands rather
than whenever someone next reads the file.

`passkey.begin` also consumed no rate limit, where passwords, magic-link, api-key and saml each bound
their entry point and `flows.signIn` has no central limiter to fall back on. It is keyed on the canonical
address when one is supplied, and on the session id otherwise. `limiterKeyPrefix` joins the other passkey
options, defaulting to `passkey:begin:`.

Refuse a revoked passkey on the branch that mints the session.

`passkey.complete` read `cred.revokedAt` for its truthiness, where the offer path twelve lines above uses
`isRevoked` and carries a comment saying why: a `revokedAt` of `0` is falsy, so a store keeping timestamps
as epoch ints would answer a revoked row and this read it as live. The same bug was found and fixed for
TOTP and for `beginWebauthnMfaVerify`, both of which now note it in place; the accept path was missed, and
it is the more consequential of the two, since the offer path only lists a credential while this one
returns `startSession`. No adapter shipped here can produce it — `Credential.Me['revokedAt']` is
`Date | null` and `new Date(0)` is truthy — so this closes it for the pluggable store contract and for
consistency, not against a live exploit. A test drives the assertion through a store answering `0` and
asserts the mismatch; with the old check it resolved to `startSession`.

Make the OpenAPI spec describe the routes the adapters actually mount.

`buildOpenApiSpec` declared a route layout the framework adapters have never mounted. Six of its nine
paths did not exist: `/password/sign-in` against a mounted `/signin`, `/sign-out` against `/signout`,
`/passkey/verify` against `/passkey/complete`, and `/oauth/{provider}/start` plus `/magic-link/request`
against the single `/providers/{id}/begin` that drives every two-step provider. The five mounted MFA
routes were absent altogether. The spec's own `info.description` calls these "routes mounted by
`@gentleduck/auth` framework adapters", so a client generated from it 404s on sign-in and sign-out. The
existing test pinned the wrong paths, which is why it stayed quiet.

The path table now follows `mountHono` one for one, `GET /session` answers a `SessionResult` envelope
rather than a bare `Session` (both members are null when nothing resolves, and that is a 200), and the
gate names match the adapters' skip flags — so `OpenApi.Cfg['providers']` takes
`'magic-link' | 'oauth' | 'passkey' | 'totp'`. `'password'` is gone, because `/signin` is mounted
unconditionally and takes any registered provider by id. **Anyone generating a client from this spec
gets different paths, which is the point: the old ones did not resolve.**

A new `openapi-route-parity` test mounts the router against a recorder and diffs it against the spec,
at default config and once per skip group, so a route added, renamed or gated on one side fails there
instead of in someone's generated client.

The four routes also advertised an `Idempotency-Key` header. `auth.idempotency` is real and works, but
it is a facet a host wraps its *own* routes in — no adapter reads the header, so the spec was promising
that a retry replays the cached response when every retry executes again, sending a second magic-link
mail or burning another rate-limit token. The parameter is dropped and a test now asserts the spec does
not mention it. Wiring the header into the adapters is a feature, not a fix, and is left alone.

Describe the sign-in response the routes actually send, and stop `SignInResult` describing one nothing does.

Correcting the paths left the schemas untouched, and they were wrong in the same direction. `SignInResult`
declared a 200 of either `{ session }` or `{ mfaRequired: true, methods }`. Neither is ever sent:
`mfaRequired` appears nowhere in the package outside this file, because a second factor is not a 200 with
a flag — `flows.signIn` throws `AUTH_STEP_UP_REQUIRED`, which the adapters map to a 401 carrying
`detail.challenge`. And a successful sign-in sends no body at all; the session rides in the `Set-Cookie`
the transport issues, which is why the client re-reads it with `GET /session`. The schema is gone, the
four sign-in completing routes declare an empty 200 with a documented `Set-Cookie` and a 401 that names
the step-up code.

This one is pinned to the wire rather than to another list: the new test drives a real password sign-in
through the mounted handler and asserts the status, the empty body and the cookie, then asserts the spec
declares no content for that 200. It failed on exactly that last assertion before the fix.

Say that the client `signUp` route is yours to mount.

`signUp` defaults to `POST /signup` and its docs named that path the way `signIn` names `/signin` — but
no adapter mounts a registration route, so the default 404s while the neighbouring default works. The
method is still worth having, since it carries the CSRF header, the same-origin credentials and the
envelope that a bare `fetch` would not; the docs now say the route is the host's and the default is a
placeholder. A test pins the three client defaults the library does back, and pins `/signup` as absent so
mounting one later cannot quietly contradict `SignUpOptions`.

Stop the client reporting a signout the server refused.

`client.signOut()` discarded the envelope `call` had just built and answered `{ ok: true }` whatever
happened — a 500, a CSRF refusal, an unreachable host. Clearing the local session regardless is right:
the caller asked to sign out, and a cached session outliving the request is worse than none. Reporting
success is not, because the session is still live on the server and the cookie is still in the browser,
which is the one thing signout exists to rule out. It now clears local state exactly as before and
returns what the server said, the way `signIn` already surfaces its failures. **Callers that assumed
`ok` is always true on this method will now see `false`, which is the point.** Two tests cover the
refused and the unreachable case; neither path had one, which is why this stood.

The `as` cast there was holding up a second untruth: the method declared
`Envelope<Record<string, never>, string>` while the route answers an empty body, so `data` is `null` at
runtime and has always been. `signOut` is typed `Envelope<unknown, string>` now, matching `signUp`, and
the cast is gone. The same declaration appeared in the react, vue, solid and svelte bindings, all four of
which delegate to the vanilla client and so carried the same lie; all four are corrected.

Cover the react client, which nothing did.

`./client/react` is a published entry point with no tests at all, while the vue, solid and svelte
bindings each have some. React hooks need a renderer and react-dom is not a dependency here, so the new
test pins what is checkable without one: that the module imports against the installed React and exports
its whole surface, so a dropped export or a broken barrel fails here rather than in someone's app.

Worth a decision, not changed here: `react` exposes `useSignUp` and `useBeginProvider`, and the `vue` and
`solid` bindings expose neither. Nothing is unreachable — every binding exposes the client itself, so
`client.signUp(...)` and `client.beginProvider(...)` are always in reach — but the hook-level surface is
uneven between siblings.

Repair a rename sweep that replaced `_` with `/` inside names that were never paths.

An earlier refactor rewrote import specifiers by replacing `duck-auth` with `auth/`, and the replace ran
over every string that shared the prefix. The import paths were cleaned up afterwards; the strings that
merely looked like them were not, and they are not the kind of thing a type-checker reads:

- `duck-auth init` scaffolded `process.env.DUCK_AUTH/BASE_URL`, which is not an environment variable
  name — it parses as a division, so the generated `auth.ts` failed to compile with
  `TS2304: Cannot find name 'BASE_URL'`. The same three names were wrong in the generated
  `.env.duck-auth`, and in what `keys generate` and `keys rotate` tell you to paste where.
- `duck-auth migrate <dialect>` defaulted to `--prefix=AUTH/` and emitted
  `CREATE TABLE IF NOT EXISTS AUTH/identities`, which no dialect will parse. The prefix is `auth_`
  again, which is also what the drizzle schemas name their tables.
- `duck-auth doctor` looked for `src/AUTH/auth.ts`, and `init` writes `src/auth/auth.ts` by default, so
  `init` followed by `doctor` could never find what `init` had just written.
- `AUTH_DEFAULT_EN_MESSAGES` keyed ten of its twelve error-code entries as `'AUTH/LOCKED'` and the like.
  The resolver falls back to the id it was handed, so every one of those lookups missed silently and
  rendered the raw code to an end user. The one key that survived is `AUTH_INVALID_CREDENTIALS` — the
  formatter quotes only keys that are not legal identifiers, so the quoting itself marks the damage.
- `DEFAULT_MAGIC_LINK_CONFIG.callbackPath` was `/AUTH/magic-link/callback`, and the provider builds the
  emailed URL from it, so every magic link sent at default config pointed at an upper-cased path.
- The vue, solid, react and vanilla clients named `@gentleduck/AUTH/client/*` in the errors they throw,
  and vue's injection key was `Symbol.for('@gentleduck/AUTH/client/vue')`.

Seventy more occurrences were test titles and failure messages naming codes like `AUTH/STALE_WRITE`,
which means grepping for an error code did not find the test that covers it.

Fix the scaffold's imports, which named symbols that no longer exist.

Separately from the rename, both `init` flavors still named the pre-`a209418d` symbols — `AuthMemoryAdapter`,
`AuthCookieTransport`, `AuthScryptHasher`, `AuthJwtTransport`, `AuthArgon2idHasher` — after that commit
stripped the `Auth` prefixes. They also imported from `@gentleduck/auth/providers/password`, which the
`exports` map does not have (it is `passwords`), named `RedisSessionStore` and `RedisIdempotencyStore`,
which have never existed in any form, took `RedisLimiter` from `adapters/redis` rather than
`limiters/redis`, and passed `env: 'production'` to `new AuthEngine`, which takes no such option. Both
templates now type-check: `tsc` on the generated output reports nothing but the unresolved imports that
`--noResolve` guarantees.

`README.md`'s examples were pinned against the `exports` map in an earlier round; that guard now runs over
the `init` output too, which is the same kind of string and rotted the same way. The CLI's own tests had
asserted `toContain('AuthMemoryAdapter')` and `toContain('RedisSessionStore')` — an assertion that a
name is present can never notice that the name resolves to nothing.

Create the scaffolded env file owner-only.

`init` wrote `.env.duck-auth` at the umask default, typically `0644`, and the file exists to hold
`DUCK_AUTH_HS256_SECRET`. It is created `0600` now; `mode` is masked by the umask, so this can only
narrow. It also reported `scaffolded <path>` for an existing env file it had deliberately left alone,
and now says `kept existing`.

Worth a decision, not changed here: `DEFAULT_MAGIC_LINK_CONFIG.callbackPath` is `/auth/magic-link/callback`
once the case is repaired, but the only magic-link route any adapter mounts is `mountHono`'s
`/auth/magic-link/verify`. The default link lands on a route that exists nowhere. Changing a public
default is a behaviour change, so the case fix is all that is applied.

Read the GitHub account's verified address, so `link-if-verified` can fire for GitHub at all.

The GitHub provider requested the `user:email` scope and then never called `/user/emails`. It took the
address from `/user`, which carries only the *public* profile email — unset by default, and carrying no
verification claim either way — and it never set `emailVerified`. `resolveFederationConflict` requires
`profile.emailVerified === true` to link, so a host that configured `onFederationConflict:
'link-if-verified'` got a policy that rejected every GitHub sign-in it was ever asked to arbitrate. It
failed closed, which is why nothing caught it: a declared feature wired to nothing.

`fetchProfile` now reads `/user/emails` and takes the row that is both `primary` and `verified`, which is
the only thing that justifies setting `emailVerified: true`. Verification is read from GitHub, never
assumed. This is best effort by design: a token whose `scopes` were narrowed, a rate limit, or an account
with no verified address all fall back to the `/user` email carried *without* a verification claim, which
is the posture the Microsoft provider already takes. Sign-in is never failed over it.

New on `OAuthClient`: `authedJson(url, accessToken, providerId)`, an authenticated JSON GET under the same
64KB body cap as `userinfo`, for any provider whose profile needs a second call. It refuses a non-http(s)
url before reaching `fetch`, because a host's own `fetchProfile` receives the client and can call it.

The provider had no test file at all — it was the lowest-covered module in the package at 16.66% of
statements. It now has nine, covering both endpoints, both fallbacks, and both federation outcomes.

Worth a decision, not changed here: Sign in with Apple cannot complete a flow, at three layers. Apple
requires `response_mode=form_post` whenever any scope is requested, and `begin()` emits `scope=name+email`
with no `response_mode`, so Apple answers `invalid_request`. The only oauth callback any adapter mounts is
a GET reading query params, so Apple's POST would 405. And the `__Host-duck-oauth` binding cookie is
`SameSite=Lax`, which a browser withholds on a cross-site POST, so the state binding check would fail with
the cookie absent. The last of those is the decision: Apple needs `SameSite=None` on that cookie, and
`Lax` is load-bearing CSRF defence for the other five providers. Full write-up in
`docs/superpowers/notes/2026-09-19-apple-cannot-complete-a-flow.md`.

Related and also unchanged: `OAuthClient.buildAuthorizeUrl` accepts `extraParams` and no caller anywhere
passes it — it is the hook Apple's `response_mode` needs. The `apple` provider requests the `name` scope,
which Apple only ever delivers in the form_post body it cannot currently receive. The `microsoft` provider
requests `User.Read` while reading only the OIDC userinfo endpoint that `openid`/`profile`/`email` cover;
that one needs checking against a live tenant before anything is removed, since it may be what forces the
access token's audience to Graph.

Declare the five optional integrations that are imported at runtime and were in no dependency field.

`@aws-sdk/client-ses`, `@opentelemetry/api`, `resend`, `twilio` and `web-push` are each loaded with
`await import('name' as string)`. The `as string` is deliberate — it stops the bundler resolving them, so
an app that never sends SMS never pays for `twilio`. It also stopped anything noticing they were declared
nowhere: no version range was expressed for any of them, and each one's own failure message told the user
to install a "peerDep" that did not exist. The sibling tell is exact: `@aws-sdk/client-kms` is loaded the
same way and *is* declared `>=3 <4` optional; `@aws-sdk/client-ses` is loaded the same way and was not.

All five are now `peerDependencies` with `peerDependenciesMeta.optional`, matching the ten that were
already there. `@aws-sdk/client-ses` takes `>=3 <4` from its sibling and `@opentelemetry/api` takes
`>=1 <2`; the ranges for `resend`, `twilio` and `web-push` are lower bounds read off the single symbol
each call site uses, so narrow them if you mean to support a specific major. Nothing is forced on a
consumer: an optional peer that is absent still fails the same way, with the same message.

`src/__tests__/lazy-peer-deps.test.ts` now pins it from both ends — every dynamically imported bare
specifier must be a declared optional peer, and every package name an error message tells the user to
install must be a real key of `peerDependencies`. The two halves found the same five independently.

Stop `mountHono` documenting a CORS middleware it does not mount.

`mountHono`'s JSDoc read "`opts.cors` mounts a scoped CORS middleware". Nothing reads `opts.cors`, and
`MountHono.App` declares only `get` and `post`, so no middleware can be mounted through that type at all —
the option is not merely unimplemented, it is unimplementable as typed. A host setting
`cors: { origins: [...] }` got silence. It fails closed, so the consequence is a broken cross-origin
integration rather than an open one. Both comments now say it is inert; **the option itself should be
implemented or removed, which is a decision, so it is left in place.**

Related comments that named a dependency field the package does not have: `hono` and `@grpc/grpc-js` were
both described as peerDeps and are in no dependency field, because both adapters are structurally typed
and neither package is ever imported. The gRPC one also called it "lazily loaded"; there is no import.

Pin what `opts.skip` actually removes.

`mountHono`'s `skip` had no test. It is also not the clean partition its names suggest: `'totp'` gates
every MFA route, backup-code regeneration included, so a host that offers backup codes but not TOTP cannot
ask for that. Documented on `SkipGroup` and pinned in `hono-skip-groups.test.ts`, which asserts each group
removes exactly its own routes and that sign-in, sign-out, session and provider-begin survive every
combination. Worth a decision, not changed here: whether that grouping should split.

Also added: `src/server/__tests__/adapter-options-wired.test.ts`, which fails when a field is added to any
adapter's `*Options` type and read by nothing — the shape `cors` had.

Make `strict({ env: 'production' })` refuse a forgeable signing secret.

The production gate checked the limiter, the stores, the idempotency store, cookie `secure`, the baseUrl
scheme, that a provider exists and that someone listens for `lockout` — seven checks, none of which looked
at the secrets those sessions are signed with. A deployment with a one-character HS256 signing key and a
one-character oauth `stateSigningSecret` passed every one of them. `strict()` is the call a host makes to
be told what is wrong before it serves traffic, so fixing the six things it did report and shipping was
the documented path to a green gate on a deployment whose session tokens anyone could mint.

RFC 7518 section 3.2 requires an HMAC key at least as long as the hash it feeds, so 32 bytes is the floor
for HS256. `AuthJwtTransport` and the oauth provider each compute one boolean at construction —
`__weakSigningKey`, `__weakStateSecret` — and `strict()` reads them by brand, the same way it already
reads `__isNoopLimiter` and `__isMemoryStore`. The brands are booleans the holder derived; neither carries
the secret, and neither is on the public type. A transport or provider that publishes no brand is not
checked, there being no way to read a foreign implementation's key. Providers are read through
`engine.providers.list()` rather than `cfg.providers`, so one supplied as a factory is checked too.

Empty is separated from short, because they are different failures. An absent `stateSigningSecret` is not
an unsigned state — `createHmac` accepts an empty key and produces a perfectly valid MAC with it, so the
state is signed with a key every attacker also has. That is refused at construction, in every environment,
rather than recorded for a `strict()` call the host may never make. A short-but-present secret is a
production policy question, so it is reported by `strict()` and only in production, matching every other
check there.

The CLI's `--production` scaffold has claimed since it was written that this call "refuses to start on a
weak secret, an insecure cookie, or a missing limiter". Two of those three were true. The comment is now
accurate as written, and `.env.duck-auth` already tells operators to use 32 bytes.

Six tests in `src/core/__tests__/strict.test.ts` cover it, including that key length is silent outside
production. Each check was mutation-proven in its own run, the floor value included.

Refuse a batch unlink that would lock an account out, and emit the event that says one happened.

`identities.unlink` refuses to drop the last way into an account: the remaining provider links plus the
live credentials must not come to zero. `identities.unlinkMany` called the store directly and applied no
such check, so the batch path — the one a bulk admin action takes — could leave an identity with no
provider and no credential, reachable by nobody. `flows.unlinkProvider` refuses the same thing twice,
before and after the write, with a rollback; the facet is simply the weaker of the two implementations.

`identity.unlinked` was declared in the event catalogue as "the mirror of `identity.linked`", with a
SECURITY note calling it "the half an account takeover performs, dropping the real owner's login so only
the attacker's route is left". `flows.unlinkProvider` emitted it. The facet did not, on either method, so
a host subscribing to it for alerting saw nothing when the write came through `auth.identities`.

Both are fixed by delegation rather than by a second copy of the check: `unlinkMany` now calls `unlink`
per row and `linkMany` calls `link`, both through the `refusable()` wrapper that already turns a refusal
into a skipped row rather than an aborted batch. A duplicated guard is what let these drift in the first
place. `linkMany` inherits the duplicate-providerId refusal the same way. `allowedLockout` is always
`false` from this facet, which is accurate: the override is `flows.unlinkProvider`'s, and this path has
none — a host that means to strand an account still has that route.

**A batch unlink that previously stranded an account now skips that row and returns without it.** The
returned array is what it always was: the rows actually written.

Record who ran a batch erasure, and stop a bulk import swallowing driver failures.

`identities.erase` takes `{ reason, operatorId }` and binds the actor so the store stamps who performed
the erasure. `identities.eraseMany` took a bare array of ids and bound nothing, so the irreversible
operation was attributable on the single path and anonymous on the batch. It now takes the same envelope
and binds the actor once around the one adapter call; omitting `operatorId` still leaves an outer
request-scoped actor alone, because `withActor(undefined)` is a fence that clears the scope rather than a
no-op. **`eraseMany(ids)` is now `eraseMany(ids, { reason })` — a required argument, matching `erase`.**
The `Identities.Store` contract is unchanged: adapters carry attribution through the actor scope.

`bulkCreate` caught every error from a row and counted it as `failed`. This file has `refusable()` for
exactly this distinction, and its comment says why: Postgres leaves a transaction aborted once a statement
has failed, so swallowing one makes a later `COMMIT` a silent `ROLLBACK`. A bulk import that lost its
connection returned `{ created: 0, skipped: 0, failed: N }` and threw nothing. A refusal this layer decided
is still a failed row; a driver failure now propagates.

`bulkCreate` in `merge` mode also linked through the store rather than through `link`, so a provider folded
into an existing account emitted no `identity.linked`. It goes through `link` now, which is also where the
duplicate-providerId refusal lives, so the inline re-check is gone.

Worth a decision, not changed here: `bulkCreate` in `replace` mode erases the account it is replacing
through the store, with no `reason` and no `operatorId`, where `erase` and `eraseMany` both require one.
An ambient actor still flows through, so attribution is possible; it is never explicit.

**Spending an MFA backup code now reaches the event bus.** `recovery.mfa.escalated` was declared on
`Events.EventMap`, listed in `AUDITED_EVENTS` so the audit envelope would be stamped onto it, and allowed
through the webhook event filter — and nothing ever emitted it. `flows.completeStepUp` accepts
`method: 'backup-code'`, rotates the session to `aal: 2` and records `backup-code` on its factor list, and
that session row was the only trace: no webhook fired and no audit subscriber could see that an account's
second factor had been satisfied without the factor. `MfaImpl.verifyBackupCode` emits it now, after the
compare-and-set claim and the revoke, so a subscriber reading the row it names finds the code already
burnt and revoked, and a losing racer emits nothing.

Breaking, at the type level only: the payload's `ticketId` is now `credentialId`, carrying the backup-code
row that was spent. duck-auth has no ticket concept — `ticketId` appeared nowhere but its own declaration —
and `credentialId` is what `mfa.ts` already calls this identifier for webauthn enrolment and in the
`suspicious` payload. Nothing emitted or subscribed to the event, so any handler written against the old
name was unreachable code.

Worth a decision, not changed here: `BackupCodesFacet.verify`, the second backup-code implementation, still
emits nothing. It is wired by the host rather than mounted on `AuthEngine` and holds no event bus, so giving
it one changes a published constructor signature — a required parameter breaks direct constructors, an
optional one puts the silent gap back as a configuration footgun.

**The `client_credentials` grant is rate-limited, and reachable.** `M2MImpl.exchange` compares a
caller-supplied `client_secret` against stored material through the same `ApiKeysFacet.verify` that
`ApiKeyProvider.complete` uses. That provider guards the call twice — a type-and-length check so a
non-string cannot throw a `TypeError` past the quota, then `limiter.consume` — and `exchange` did neither,
leaving an unbounded online guessing oracle for service-account secrets.

`M2MImpl` now takes a `Limiter.Me` as its fourth constructor argument, ahead of the optional config, and
`m2m()` takes one in the same position. The quota is keyed on `clientId`, not on the presented secret: a
brute force sends a different secret every attempt, so keying on the secret hands every guess a fresh
budget and bounds nothing. `clientId` and `clientSecret` are now required to be strings of at most 512
characters, checked above the limiter so an unbounded id cannot become an unbounded limiter key. This is a
breaking constructor change for anyone constructing `M2MImpl` directly — which, until this release, was
nobody outside the package, because of the next paragraph.

`@gentleduck/auth/core` exported `type { M2m }` and no runtime symbol, so the grant could not be reached:
a host could name `M2m.ExchangeInput` and had no way to obtain anything that accepts one, while the class
docstring told them to mount a `/oauth/token` route calling `exchange()`. `M2MImpl`, `m2m` and
`DEFAULT_M2M_CONFIG` are now exported from `./core`. The root export surface is unchanged.

**An impersonation can name the authorization that allowed it.** `identity.impersonated` has always
declared an `iamDecisionId`, documented as "the one entry an audit log cannot afford to be missing", and
the field appeared exactly once in the package — in that declaration. No option carried it, the only
emitter never set it, nothing read it. `Flows.ImpersonateOptions` now takes `iamDecisionId`, validated to
1–256 characters like the `reason` beside it, and it reaches the event. An impersonation that names no
decision publishes no key at all rather than an explicit `undefined`.

Not changed here, and worth a decision: `flows.impersonate` still accepts an arbitrary `authorize`
callback, so the declared `AUTH_IMPERSONATE_REQUIRES_IAM` is thrown by nothing and an impersonation with no
IAM decision behind it remains possible. Requiring one is a breaking policy change.

Also reported, not changed: `OAuth.StatePayload.nonce` is documented "one-time use" and nothing enforces
it. The nonce is minted, signed, round-tripped and shape-checked, but never recorded or compared, and
`AUTH_OAUTH_NONCE_REPLAY` is declared for the violation and raised by nothing. `DPoPVerifier` already
enforces the same property through a nonce store, and both a memory and a Redis store ship, so the
machinery exists — but the oauth provider holds no store, and adding an optional one would put the silence
back as a configuration footgun.

**`FakeRedis` now expires keys of every type, not only strings.** The in-process redis used by every unit
test of the redis-backed stores — and exported publicly on the `./test` subpath — held its TTLs on string
entries, so `EXPIRE` on a set or a sorted set answered `0` and set nothing. `RedisSessionImpl` keeps its
per-identity session index in a set and bounds it with one `expire` call; against this fake that call did
nothing, so the index was unbounded in every test that has ever run. TTLs now live in one map keyed by the
key, a bare `SET` drops a prior TTL as real Redis does without `KEEPTTL`, `DEL` clears it, `INCRBY` keeps it
so a rate-limit window survives its own increments, `SCAN` walks sorted sets too, and every set and
sorted-set read consults expiry first.

**Passkey registration can request direct attestation, and `strict()` now checks that it does.**
`Passkey.Options` gains `attestationType` (`'none'` by default); the registration call hardcoded `'none'`,
so the `fips` compliance preset's `webauthnAttestationDirect` requirement was unreachable on that path
while `mfa`'s WebAuthn enrollment honoured the same option. `strict()` now reads the setting off the
registered passkey provider instead of taking the operator's word, and observed evidence takes precedence
over a supplied attestation — a deployment can no longer claim `limiterRequired` while holding the Noop
limiter.

**The sqlite adapter waits for `pragma foreign_keys = on` before answering.** It was issued fire-and-forget
in the constructor. A raw driver sets it synchronously through `exec` first, but the adapter also accepts a
drizzle handle you already have, and for an async one the first queries ran with foreign keys still off —
the state that leaves dangling provider links behind an erased identity. The pragma is now awaited at the
boundary every facet calls through, and a pragma that fails surfaces as an adapter error instead of an
unhandled rejection on an unenforced connection.

**`RedisEvents` reports a fan-out it could not perform.** A rejected `publish` was answered with `() => 0`,
so `emit` resolved as success while no other node in the fleet received the event and nothing recorded it.
The failure is now logged with the event name, and `emit` still resolves — local handlers have already run,
so a redis blip does not become a failed sign-in.

**The session stores with no schema now enforce the constraints the SQL ones do.** `assertSessionAllowed`
carried three of the seven `CHECK` constraints every dialect declares, so memory, redis and valkey accepted
a session id that was not a 64-character hash, a deadline preceding the row's own creation, a rotation
preceding it, and an absolute cap below the sliding expiry. The first of those let a caller use the bearer
token itself as the primary key; the last left the session with no absolute cap at all. The shared store
compliance suite defaulted session ids to a raw label that every SQL adapter overrode away, so it had been
asserting a different contract on either side of the divide it exists to erase — it now hashes by default.

**`strict({ env: 'production' })` now refuses the in-process limiter.** It rejected the in-process stores by
brand but checked only `AuthNoopLimiter` for the limiter, so a deployment supplying `AuthMemoryLimiter` — or
relying on the engine's fallback to it — passed the production gate holding a class whose own docstring reads
"Dev/test only". Across a fleet that grants every brute-force budget once per node, and a restart returns all
of them. It also reached the compliance evidence, which positively reported `limiterRequired` satisfied for
it and, since engine evidence takes precedence, overrode an operator attesting otherwise. **Breaking for any
production deployment currently passing `AuthMemoryLimiter` or omitting a limiter: `strict()` will now refuse
to boot. Wire `AuthRedisLimiter`, or your own.** The in-process events bus, passkey challenge store and DPoP
nonce store remain unchecked and are reported in the audit log rather than changed here.

**An expired session is refused even when the cleanup write fails.** `getBySid`, `touch` and `resolveBySid`
delete the dead row before throwing `AUTH_SESSION_REVOKED`, and that delete was awaited unguarded — so a store
that refused the write returned `AUTH_ADAPTER_FAILED` in the refusal's place. That code is not in `ABSENT`, so
the `resolveSession(...).orNull()` every server adapter calls rethrew it and a merely-expired session came back
as a 500 instead of a 401. The cleanup can no longer change an answer that was decided before it ran.

**A signup flow token now expires.** `beginSignUp` writes two deadlines — the credential's 24-hour absolute
cap and `flow.expiresAt`, the sliding thirty-minute window every `advanceSignUp` pushes forward — and only the
read path checked the first, while nothing anywhere compared the second against the clock. `advanceSignUp` and
`completeSignUp` therefore accepted a flow token at any age, and `completeSignUp` mints a session, marks the
address verified and merges the staged profile. Nothing swept the row either, the credential store contract
having no `gc`, so an abandoned signup's token stayed a valid account takeover indefinitely. The three entry
points now share one liveness check, and each still answers with its own error code.

**The in-process identity store now enforces the identity constraints every dialect declares.** Both logins
must be a non-empty string and fit their column (320 / 191), and neither half of a provider link may be
blank — the five `chk_auth_identities_*` and `chk_auth_identity_providers_*` constraints pg, mysql and sqlite
all carry, and which the memory store and the identities facet checked nowhere. A blank, missing, non-string
or over-long `username`/`email` was written in dev and refused on the first production write, and such a row
is not findable by the address it was meant to carry, since the uniqueness pass reads a blank login as
absent. **Breaking for a host whose `profileToIdentityProfile` can yield a blank address** — the shape most
of them are written in — which now fails at the store rather than silently in dev only.

**A session that timed out now says so.** `AUTH_SESSION_EXPIRED` — declared with an `{ expiredAt }` meta and
translated in `i18n` — was raised by nothing; every deadline threw `AUTH_SESSION_REVOKED`, which is also what
a store answers for a row that is absent, corrupt or another tenant's, and whose only detail is a free-text
`reason`. `getBySid`, `touch`, `resolveBySid` and the JWT transport's `exp` check now raise the expiry code
and name the instant, so a caller can tell "sign in again" from "this session was revoked". The code joins
the absent set in the same change, so `resolveSession(...).orNull()` still reads a timed-out session as
absence rather than an error. **Breaking for a caller matching on `AUTH_SESSION_REVOKED` to detect a timeout**
— match `AUTH_SESSION_EXPIRED`, or both. The store layer is unchanged. A further ten declared error codes are
raised by nothing at all; they are listed in the audit log rather than changed here.

**A stateless transport's verdict now survives the store fallthrough.** `resolveSession` verifies the token
with the transport and, where that does not vouch for it, falls back to looking the token up as a session id
— which is what lets one engine accept both a cookie sid and a bearer JWT. That fallback also ran for a token
the transport had authenticated and then refused, and since the store is keyed by sid hash it can hold no row
for a minted token, so its `no session for that sid` overwrote the real answer: an expired JWT reached the
caller as `AUTH_SESSION_REVOKED`, never as `AUTH_SESSION_EXPIRED`, through `resolveSession` and through
`CompositeTransport` alike. `AUTH_SESSION_EXPIRED` is the one refusal a transport reaches only about a token
whose signature verified — every "not a token of mine" rejection is `AUTH_SESSION_REVOKED` — so it is now
kept and answered, and every other refusal still falls through exactly as before. **Breaking for a caller
matching `AUTH_SESSION_REVOKED` to detect an expired bearer token**, which is the same move as the change
above and now reaches the path server adapters actually take.

**`strict()` now rejects the two dev-only implementations `NODE_ENV` was the only thing guarding.**
`MemoryIdempotency` and `AuthNullCaptchaVerifier` each refuse to construct under `NODE_ENV=production`, but
`strict({ env: 'production' })` is a separate declaration and most runtimes leave `NODE_ENV` unset, so on
those deployments nothing refused them. `strict()` covered only half of its own stated intent — it caught an
*omitted* idempotency store, not the same class wired by name, which is what the README example does — and
never looked at the captcha verifier at all. Both are now rejected by brand, the way the memory adapter and
the in-process limiter already are, and `IdempotencyImpl` republishes its store's brand so the gate reads it
without reaching into private state. An always-pass captcha removes protection from every path it fronts; the
unconfigured verifier, which refuses every challenge, is still accepted, because failing closed is not a
footgun. **Breaking for a production deployment that was wiring either one** — which is the point: it was
unprotected and silent about it.

**`duck-auth doctor` now runs.** The command imports your `auth.ts` and calls `strict()` on its `auth`
export — with no arguments, though `strict(opts)` reads `opts.compliance` before anything else. Every
invocation died on a `TypeError` that the surrounding catch reported as
`strict() rejected: Cannot read properties of undefined (reading 'compliance')`, so a healthy config and a
broken one were equally "rejected" and no check ever ran. It now asks about `production`, the only env whose
checks exist; prints `meta.detail`, which is where the list of failed checks lives, rather than
`AuthError.message`, which is the bare code `AUTH_MISCONFIGURED`; and says `could not run strict()` for a
failure that is not a verdict, so a crash can never again read as a finding.

**`strict()` now checks every store you hand it, not three of them.** The production sweep for in-memory
stores was a hand-written list of `identities`, `sessions` and `credentials`, under a comment reading "over
every store". `Engine.Stores` has a fourth slot: `orgs`. The memory adapter's org store carries the same
`__isMemoryStore` brand the sweep looks for, so a deployment with real identity, session and credential
stores beside `adapter.orgs` passed the gate while its membership rows and role grants — an authorization
input — lived in one process, invisible to the rest of the fleet and emptied by a restart. The sweep now
reads the stores bag itself, so `orgs` is covered and a slot added later cannot be missed. `Org.Store` is a
read interface over your own tables, so a production host is expected to have one already; the memory store
is the dev stand-in. **Breaking for a production deployment wiring `adapter.orgs`** — wire your own org
store, or leave `orgs` unset if the app has no org concept.

**The memory device-fingerprint store now refuses a bound it cannot apply.**
`AuthMemoryDeviceFingerprintStore` caps how many device fingerprints it remembers per identity and expires
them after a TTL, and applied both as a bare `>` against the configured number. Every comparison against
`NaN` is false, so a non-finite `maxPerIdentity` or `ttlMs` -- `Number(process.env.FP_MAX)` on an unset
variable, say -- did not widen the bound, it removed it: one identity retained 500 fingerprints where the
default caps at 50, and no sighting ever expired. Zero and negative failed the other way, remembering
nothing, so every request read as a new device and stepped up at the detector's default score. Both are now
validated in the constructor and throw `AUTH_MISCONFIGURED`, matching `deviceFingerprintDetector` and
`authImpossibleTravelDetector`, which already validated their own numeric config. **Breaking only for a
config that was already not working**: the value that now throws was previously disabling the bound it was
meant to set.

**The SSRF guard now refuses internal host *names*, not only internal addresses.** `isBlockedHostname`
recognised four spellings of `localhost` and nothing else, so `metadata.google.internal` -- the name GCP's
metadata server answers on, and what an SSRF payload targeting GCP actually uses -- passed the guard that
already refuses the 169.254.169.254 behind it. Also now refused: `metadata.goog`, anything under the
ICANN-reserved `.internal`, and the `localhost4` / `localhost6` / `ip6-localhost` / `ip6-loopback` aliases
that ship in the /etc/hosts of Debian-family images. Applies to every outbound URL the library checks:
webhook endpoints, captcha verify endpoints and web-push subscription endpoints. **Breaking for a
deployment that points any of those at a `.internal` host** -- which was already the case for `.local` and
every RFC 1918 address, so this extends an existing posture rather than introducing one.

**Outbound oauth and captcha requests no longer follow redirects.** `OAuthClient`'s code exchange, refresh,
userinfo and `authedJson` calls, and the captcha siteverify POST, all left `fetch` on its default
redirect-following behaviour, so the request did not necessarily land on the endpoint the scheme and SSRF
guards had checked. A 307 or 308 from a token endpoint re-posts the body with `client_secret` in it to
whatever the `Location` names, and a redirect to `http://` puts that secret -- or the bearer token on the
userinfo call -- on the wire in plaintext. All five now pass `redirect: 'error'`, the posture the webhook
dispatcher already took. **Breaking for a provider whose token, userinfo or captcha endpoint answers with a
redirect**: point the config at the final URL instead.

**The Redis/Valkey event bus no longer goes deaf to the fleet when a handler is swapped.** `RedisEvents.on()`
recorded a channel teardown by deleting its `_subscriptions` entry synchronously and issuing the
`UNSUBSCRIBE` several awaits later. Because the shipped valkey adapter unsubscribes a *channel* rather than a
callback, an `on()` for the same event in that window -- `unsub(); bus.on(event, next)`, the ordinary handler
swap -- opened a second subscription that the in-flight teardown then cancelled, and the map was left holding
a live-looking entry so no later `on()` resubscribed. The node kept delivering its own local emits and kept
reporting a listener to `strict()`, while receiving nothing from other nodes for `lockout`, `session.revoked`
or `suspicious`. The teardown now stays in the map while it runs and resubscribes if a handler arrived
meanwhile. Not breaking: same public surface, and a bus that never swaps handlers behaves as before.

**CSRF: bearer clients are no longer refused by the NestJS auth guard, which now also takes a `cfg`.**
`verifyCsrf` only applied its documented bearer exemption when a caller passed `isBearer`, and the helper
that detects one is module-private -- so `csrfGuard` was the only caller that ever set it. NestJS'
`makeGuard` calls `verifyCsrf` directly (to reuse the session Nest middleware already resolved) and passed
neither `isBearer` nor a `Csrf.Cfg`, so a client authenticating with `Authorization: Bearer <session token>`
was refused `AUTH_CSRF` on every mutating route, and a configured `allowedOrigins` / `headerName` was
ignored where the CSRF-only guard beside it honoured them. `verifyCsrf` now derives the flag from the
Authorization header when it is not told, and `makeGuard` accepts `cfg`. An explicit `isBearer` still wins.
The exemption itself is unchanged -- still only when no cookie rides along, still held to the origin checks
otherwise. **Behaviour change for a NestJS app using `makeGuard` with bearer clients**: those requests now
pass the CSRF check instead of being rejected, matching every other adapter.

**`WebhookDeliverer` now refuses a `maxAttempts` or `timeoutMs` that would stop delivery silently.**
`maxAttempts` was clamped rather than validated, and `Math.min(Math.max(1, NaN), 20)` is `NaN`, so a
non-finite value made the retry ladder's `while (attempt < maxAttempts)` false on the first pass: no request
was made for any event and the delivery was dead-lettered with `attempts: 0` and an empty `lastError`.
`timeoutMs` was not checked at all, and `setTimeout` floors a negative or non-finite delay to zero and
overflows past 2^31-1 to zero too, aborting every request before it left. Both now throw
`AUTH_MISCONFIGURED` at construction, as `backoffMs` beside them already did. The clamp on a *finite*
`maxAttempts` is unchanged. **Breaking for a deployment passing a non-finite `maxAttempts` (including
`Infinity`, which the clamp silently turned into 20) or a `timeoutMs` outside `[1, 2147483647]`** -- those
configurations were not delivering webhooks, and now say so at boot.

**Every store's `gc(now)` now refuses a cutoff that is not a finite timestamp.** The nine implementations
across memory, SQLite, Postgres, MySQL and Redis each compared rows against `now` directly and disagreed
about a number that is not one: `NaN` swept nothing and reported `deleted: 0` on memory, SQLite and Redis
while Postgres threw, and `Infinity` deleted **every** session on memory and Redis while SQLite swept
nothing. The silent half is the likely one -- `Number(process.env.GRACE_MS)` is `NaN` when the variable is
unset -- and for identities it meant the hard-delete that makes a soft delete a delete never ran, while
reporting success. All nine now throw `AUTH_INVALID_PARAMETERS`, and the store-compliance matrix asserts it
on all six dialects along with the fact that nothing was swept before the refusal. `auth.sessions.gc()` and
`auth.identities.gc()` are unaffected -- they take no argument and pass `Date.now()` themselves. **Breaking
only for a caller passing a non-finite cutoff straight to a store**, which was not collecting anything, or
was collecting everything.

**A TOTP enrollment can no longer be started over a confirmed one.** `mfa.beginTotpEnrollment` deleted every
`totp` credential for the identity before minting the pending one, so starting an enrollment removed the
second factor. The mounted `POST /auth/mfa/totp/begin` route asks only for a signed-in session, which made it
the unguarded way to do what `/auth/mfa/totp/remove` demands a step-up for -- and a better one, since it also
returned a secret the caller controls and `confirmTotpEnrollment` then regenerated the backup codes. It was
invisible as well: `removeTotp` is what emits `mfa.removed`, so the deletion reached no audit log. It now
throws `AUTH_MFA_REQUIRED` when a live confirmed enrollment exists; re-enrolling goes through `removeTotp`,
which is guarded. Replacing a *pending* enrollment still works as before.

**Regenerating the MFA backup codes now requires a step-up.** `POST /auth/mfa/backup-codes/regenerate` took
any signed-in session and answered with ten fresh plaintext backup codes, each of which `completeStepUp`
accepts as a second factor -- so a caller holding only the password reached AAL2 in one round trip, and the
victim's codes were destroyed to mint them. The route now refuses with `AUTH_STEP_UP_REQUIRED` unless the
session is already AAL2, the same gate `/auth/mfa/totp/remove` uses.

**The last-factor lockout guard now agrees with itself.** `flows.unlinkProvider` and `identities.unlink` each
carried their own idea of what still authenticates an identity, and each allowed a lockout the other
refused: the first counted an *expired* password or passkey as live, the second counted one-shot `recovery`
tokens and second factors such as `totp` as standing ways in. Both now use `isStandingFactor` -- live,
unexpired, and of a kind that can start a session on its own (`password`, `passkey`, `api-key`).

**SAML: the email/nameID agreement check now reads the assertion, not the SP config.** It fired whenever
`allowedNameIdFormats` merely *listed* `emailAddress`, so an SP accepting `persistent` alongside it refused
every persistent login -- an opaque nameID never equals an email. It now keys on the format the assertion
states, falling back to the previous behaviour when the IdP omits one. An `emailAddress` assertion whose
email disagrees with its nameID is still refused.

**`anomalyFacet` now refuses a threshold or timeout that is not a usable number.** `threshold`, `stepUpAt`
and `denyAt` must be finite and within 0..1, and `detectorTimeoutMs` finite and between 1 and 2^31-1. All
four were taken on trust while both shipped detectors validated their own config, and every way they could
be wrong failed open: `score >= NaN` never denies and never steps up, and a delay `setTimeout` cannot use
abandons every detector before it answers, leaving `evaluate` reporting no signals at all.

**Channel sends silently stopped happening on a misconfigured retry ladder.** `ChannelGuard` — which every
shipped channel (`smtp`, `resend`, `ses`, `twilio`, `webpush`) constructs from its own public `Cfg` —
applied `retries` and `timeoutMs` without validating either. A non-finite or negative `retries` made
`tries <= this._retries` false on the first test, so the provider was never called and the guard threw
`undefined`; `Infinity` turned the doubling backoff into a tight loop, since `setTimeout` overflows past
2^31-1 and floors to ~1ms. A non-finite `timeoutMs` skipped the `<= 0` branch that disables the deadline
and reached `setTimeout` anyway, aborting every send before it left. Password resets, magic links, email
verification and account-deletion confirmations stopped being delivered, with nothing an error mapper could
render. Both are now refused at construction with `AUTH_MISCONFIGURED`: `retries` finite in 0..10,
`timeoutMs` finite in 0..2147483647. Both documented zeroes stay legal. This is the sibling of the webhook
deliverer ladder fixed earlier in this changeset — same shape, second implementation.

**Both rate limiters could be configured into not limiting at all.** `AuthMemoryLimiter` and `RedisLimiter`
validated the `weight` and `key` passed to `consume`, but applied `max` and `windowMs` from config
unchecked. Measured: `max: NaN` produced **zero refusals in fifty consumes on one key** in both limiters —
`count > NaN` is false forever — so the brute-force defence that `strict({ env: 'production' })` refuses to
boot without was silently not running. `windowMs: NaN` or `0` is the inverse: the bucket never elapses, so
the first budget spent is the last and `resetAt` reads `Invalid Date`. Both are now refused at construction
with `AUTH_MISCONFIGURED` — `max` finite in 1..`Number.MAX_SAFE_INTEGER`, `windowMs` finite in
1..8640000000000. **Breaking for anyone passing `Infinity`**: an unlimited limiter is a contradiction, and
`NoopLimiter` is the declared way to have none — unlike `Infinity`, `strict()` can see and refuse it.

**A DPoP proof from any point in time was accepted when the freshness window was misconfigured.** The RFC
9449 4.2 check is `Math.abs(now - iat) > clockSkewMs + freshnessMs`, and `>` against a non-numeric sum is
false, so the check never fired. Measured: with `clockSkewMs: NaN`, real ES256 proofs dated one year old,
ten years old, and one year in the future were all accepted — while a default verifier correctly refuses a
one-hour-old proof. Freshness is the primary limit on replaying a captured proof, and the default `jti`
store is per-process, so a fleet has no second line. `DPoPVerifier` now refuses `clockSkewMs` or
`freshnessMs` that is not a number between 0 and 3600000, with `AUTH_MISCONFIGURED`.

**A caller could switch off session-hijack and anomaly checks by omitting one header, on the Next.js and
gRPC adapters.** `requestSecurity` treated "the host supplied no `getCaller`" and "this request carried no
fingerprint" as the same early return, and every adapter collapsed the two at the call site with
`?? {}`. `nextCaller` and `grpcCaller` deliberately resolve no IP — a Web `Request` has no peer, and the
library will not read a forwarded header — so on those two adapters the User-Agent is the entire
fingerprint, and dropping it skipped the hijack evaluation, the `suspicious` audit record and the anomaly
snapshot alike. `Hijack.Cfg.onMissingSignal: 'strict'` exists for exactly that move and was unreachable,
because the return happened before the policy was consulted. Adapters now omit `caller` entirely when no
`getCaller` is configured, and `requestSecurity` only skips on that. Behaviour is unchanged on the default
`onMissingSignal: 'soften'` except that the drift is now recorded; hosts on `'strict'` get the reaction
they configured. A session that recorded no fingerprint is unaffected.

**The default password hasher reported a broken install as a wrong password, and threw on a corrupt hash.**
`Argon2idHasher.verify` returned `argon.verify(...)` without awaiting it, so its `catch` was unreachable: a
malformed PHC string rejected out of a method documented to answer `false`, which also let a corrupted
credential row distinguish itself from a wrong password despite the uniform-timing construction around it.
The same `catch`, once reachable, swallowed the `AUTH_MISCONFIGURED` that `loadArgon2` builds to carry the
`@node-rs/argon2` install command — and since `DEFAULT_PASSWORDS_CONFIG` selects Argon2id while that package
is an *optional* peer dependency, a deployment that loses the native module told every user "invalid
credentials" and the operator nothing. The module load now sits outside the `catch` and the verify is
awaited inside it. A hash from another algorithm still answers `false` without loading anything.

**`strict()` no longer refuses every HIPAA and FIPS deployment.** The AAL-floor gate asked
`providers.list()` whether an mfa provider was registered. `list()` is the sign-in grid and keeps only
capabilities exposing `begin`/`complete`; `MfaImpl` exposes `enroll`/`verify`, so it was registered and
never listed. Both presets that raise the floor above AAL 1 therefore threw `AUTH_MISCONFIGURED` saying no
mfa provider was registered while one was, in every environment. It now asks `providers.has('mfa')`.

**The FIPS hasher requirement is now verified rather than attested.** `fips` declares
`fipsValidatedHasher`, meaning "Argon2id with FIPS params", and `ARGON2ID_COMPLIANCE` — those exact params,
exported by the package — was referenced by nothing: a fips deployment running scrypt booted `strict()` on
the operator typing `true`. `Argon2idHasher` and `ScryptHasher` now publish whether they meet that
parameter set, and `strict()` reads it off the registered password provider. A hasher that publishes no
answer is still attested for, since FIPS 140 approves no Argon2 and a host may hold a validated
implementation of its own. Also: `Passwords.Cfg.hasher` was documented as defaulting to scrypt; it defaults
to Argon2id.

**Backup codes and trusted-device tokens now refuse a length that is not a secret.** `mfa({ backupCodeLen:
0 })` minted ten codes that were all the literal `-`, and `verifyBackupCode` accepted `-` for any identity;
a count that was not a positive whole number deleted an identity's codes and minted none. The same knob was
unchecked on `BackupCodesFacet` (`byteLength`, `count`) and `RememberMeFacet` (`byteLength`, `ttlMs`). All
three constructors now throw `AUTH_MISCONFIGURED` for a value outside the usable range, the way
`toApiKeysCfg` already did for `randomBytes`. **Breaking** for a deployment that configured a shorter code
than the new floors: `backupCodeCount`/`count` 1-64, `backupCodeLen` 8-64, `byteLength` 5-64, remember-me
`byteLength` 16-128.

**Both password hashers now bound their own parameters.** `scryptHasher({ keylen: 0 })` and
`({ saltLen: 0 })` each wrote a row that `parse` refuses, so sign-up succeeded and the correct password
never verified again; `({ N: 2 })`, `({ r: 0 })` and `argon2idHasher({ memoryCost: 8, timeCost: 1 })` were
accepted end to end, with `needsRehash` calling each result current. The constructors now throw
`AUTH_MISCONFIGURED` for a structurally invalid set — including an `N` too large for the `maxmem` both
calls pass, which previously threw inside Node on the first sign-up — and `strict()` refuses a hasher below
its own defaults in production only, so a test suite can still use a cheap KDF. A hasher of your own is not
judged. **Breaking** for a deployment configured below `keylen` 16, `saltLen` 8, `hashLength` 16 or
`saltLength` 8, or running production below `N` 2^14 / `r` 8 / `keylen` 32 / `memoryCost` 19456 /
`timeCost` 2.

An elapsed `expiresAt` now refuses a credential everywhere, not only on API keys. `ApiKeyImpl.verify`
already treated an expired row as a revoked one, and `isStandingFactor` — which both lockout guards use to
count the ways back into an account — already refused an expired `password`, `passkey` or `api-key`. Seven
gates read `revokedAt` alone: the password sign-in and rehash paths, the passkey `allowCredentials` offer
and the branch that mints the session, `remaining()` and `verify` on `BackupCodesFacet`, and
`MfaImpl.verifyBackupCode`. A password carrying a rotation deadline signed in for ever after it passed,
while the engine simultaneously refused to unlink that account's last provider on the grounds it would
become unreachable. `beginPasskeyRegistration`'s `excludeCredentials` is unchanged, so re-enrolling an
expired authenticator is still the way back. **Breaking** for any deployment that writes `expiresAt` on a
credential through the store contract and relies on it being ignored.

`CookieTransport`'s CSRF companion cookie now follows the session cookie's settings instead of four
hardcoded literals. `{ domain: '.example.com' }` — the option that exists for cross-subdomain deployments
— used to emit the session cookie for the whole domain and the companion as `__Host-duck-csrf` for the
issuing host alone, so a page on a sibling subdomain could not read the token, could not send
`x-csrf-token`, and had every state-changing request refused `AUTH_CSRF` with nothing said. `sameSite` and
`path` diverged the same way, and over plain http the `__Host-` prefix had the browser discard the cookie
entirely — previously documented as a `WARN` rather than fixed. The prefix is now kept exactly when its
three conditions hold, `revoke()` clears under the attributes it set, and a `csrfCookieName` getter
exposes the result for the client's existing option of that name. **Breaking**: the companion is named
`duck-csrf` when `domain` is set, `path` is not `/`, or `secure` is `false`; the default is unchanged.

`DPoPVerifier` now holds a proof's `jti` until that proof stops being acceptable, rather than for
`clockSkewMs + freshnessMs`. The freshness check is two-sided, so a proof is live for twice that span, and
the old TTL covered only the half after `iat` — measured at the defaults, the verifier asked for a 90s TTL
on a proof that stayed fresh for another 179s, and the identical proof replayed successfully once its
`jti` had aged out. The gap is how far ahead the client's clock runs, which is what `clockSkewMs` exists
to tolerate. `NonceStore` implementers should honour the `ttlMs` they are handed per key rather than
assuming one global window.

`WebhookDeliverer` now stamps each delivery attempt as it is sent. Every attempt on the retry ladder used
to carry the first one's timestamp, so a retry arrived bearing its position on the ladder as an age, and
`verifyWebhookSignature` refuses a stamp past its tolerance — 5 minutes by default — with a bare `false`,
the same answer as a wrong secret. The defaults stay inside the window, but `backoffMs: 60_000` puts
attempt 5 at 7.5 minutes and the documented `maxAttempts: 20` puts attempt 20 a day and a half out, and
both are validated as supported. The body keeps the event time so a delivery's attempts stay
byte-identical for idempotency on `deliveryId`; read freshness from the `X-Duck-Timestamp` header, which
is what the verifier takes.

Email addresses are now folded — trimmed, lowercased and NFC-normalised — when an identity is written,
rather than left for each dialect's unique index to fold on read. SQLite's `lower()` is ASCII-only, and
its `create` leans on that index alone, so an address carrying one uppercase non-ascii letter took a row
that nothing could find afterwards: measured, `find` by the exact address used to create the account
answered `AUTH_IDENTITY_NOT_FOUND` immediately after creating it, and a second account on the same address
was accepted. Sign-in by email, password reset and duplicate detection all missed the same way. Trimming
closes the same hole for a padded address on every dialect. **Breaking, mildly**: `profile.email` now
comes back trimmed and lowercased; existing rows are untouched and stay reachable, since lookups still try
the stored spelling alongside the canonical one.

`isSessionFresh` now bounds the freshness window at both ends, as `JwtTransport.verify` and `checkStepUp`
already did. A `rotatedAt` ahead of the clock gave a negative age, which is under any window, so a session
stamped a day out read as permanently fresh — and freshness is what gates a password change. Nothing
bounds that column from above and the stamp is written by whichever node rotated the session, so one
machine with a fast clock handed the rest of the fleet sessions that never went stale. Ordinary node skew
inside the window still reads fresh.

`IdempotencyImpl.handle` now releases the key when the executor throws. The claim was written with the
response TTL — a day by default — and nothing let go of it, so a client retrying under the same key after
an error read a miss, lost the claim, polled out and was answered `409 idempotency-conflict` for the next
24 hours, with the work never running again. That is the one case an Idempotency-Key exists for. A
response the executor did return is still cached and still not re-executed; a process that dies
mid-executor still falls back to the TTL.

`MfaImpl` now treats an elapsed `expiresAt` as revocation, as every other credential kind already did.
Six readers - both TOTP paths, both WebAuthn-MFA paths and the two `has*` probes - filtered on `revokedAt`
alone, so a deadline written on a `totp` or `webauthn-mfa` row was honoured by nothing: the second factor
kept verifying past it, the assertion challenge kept offering the credential, `hasTotp` kept reporting the
enrolment to `beginPasswordReset`, and the enrolment guard kept refusing to replace it. A credential whose
deadline has not passed, or that has none, behaves exactly as before.

`AuthEngine.strict()` now rejects `AuthConsoleChannel`, `AuthNoopChannel` and `AuthTestChannel` in
production, as it already rejects the memory adapter, the in-process idempotency store and the
always-pass captcha verifier. Each of the three refused itself on `NODE_ENV` and nothing else, and that
check does not fire where `NODE_ENV` is unset - so a deploy could log every magic link to stdout, or
report every password-reset email as delivered without sending one, and pass `strict()`. The three now
publish a brand `strict()` reads off the `channels` bag; a real channel is untouched, and all three stay
accepted under `env: 'development'` and `'test'`.

`IdentitiesImpl.exportAll` now narrows its session list to the tenant context it is given, as it already
narrowed the credential list one line above. The GDPR right-to-access blob read every session the identity
had anywhere, so in a multi-tenant deployment one tenant's export named the other tenant's sessions and
carried their `tenantId`, IP, user-agent, fingerprint, assurance level and factor list. Identities are
global while sessions are tenant-scoped, which is what makes the unfiltered read cross a boundary. A caller
that passes no tenant, which is every single-tenant deployment, gets exactly the same export as before.
