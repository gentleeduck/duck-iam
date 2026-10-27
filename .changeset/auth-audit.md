---
'@gentleduck/auth': minor
---

**A SAML client told `audience: false` is refused.** `samlProvider` accepted a `@node-saml/node-saml` client with
the audience check turned off. `AudienceRestriction` is not one binding among several: node-saml 5.1.0 parses the
bearer `Recipient` and the response `Destination` and compares neither against this Service Provider, so with the
audience check off any assertion the IdP ever signed — including one minted for a different SP it serves — mints a
session here. The constructor now throws `AUTH_MISCONFIGURED`, as it already does for a client that verifies no
signature at all. Pass `allowAnyAudience: true` to keep the old behaviour, or set the client's `audience` (its
`issuer` is the default). If your config now throws, it was accepting assertions for other Service Providers.

**A password alone no longer signs in an account with a second factor.** `flows.signIn` answered an AAL 1 session
to the password, a magic link, or an OAuth or SAML sign-in of an account holding a TOTP, a security key, a passkey or
backup codes. Only a route that called `checkStepUp` asked for the factor, so every route that did not served the
account to whoever held the password. A person's sign-in that did not present the account's other factor now opens
no session: it answers `challenge`, a single-use token with the `methods` that answer it, and
`completeStepUp({ challenge })` opens the session at AAL 2 once a factor checks out. The token is stored hashed,
lasts five minutes, and survives a wrong code inside the per-identity limit a step-up spends; two answers racing on
it open one session. A newer challenge for the account retires it, and so does a password reset. A passkey that
verifies the user is both factors and still signs in at AAL 2, and an API key's session is unchanged.

**Breaking: a sign-in can stop at its second factor.** `SignInOutcome` is a union on `challenge`: when it is set,
`session` is null, `sid` is empty and `intents` opens no session, so a route that ignores it signs nobody with a
second factor in. Hold `challenge.token` for the second step, in an httpOnly cookie for a browser, and answer it:

```ts
const { challenge, intents } = await auth.flows.signIn({ providerId, input, previousSid, rememberedDevice, ...caller })
// With a challenge, keep challenge.token; without one the session is open, as before.

const { intents: opened } = await auth.flows.completeStepUp({ challenge: token, method, code, previousSid, ...caller })
```

`completeStepUp({ currentSid })` still steps up a live session, but the AAL 1 session a second-factor page used to
step up is no longer minted. `signin.success` fires when the challenge is answered, not at the first step. The engine
now reads a remembered device: pass its token as `rememberedDevice`, and a live one of the same identity skips the
challenge at AAL 1, so `checkStepUp` still guards whatever needs AAL 2. A provider's `requireMfa` beside
`startSession` is challenged even from a remembered device, and still throws `AUTH_STEP_UP_REQUIRED` when the account
has no second factor to ask for.

**A password alone no longer changes an account's other factors.** Once an account held a factor beside the
password, a session that had presented only the password could still add a passkey or a security key, each of which
steps up by itself, so the second factor was never met again. It could also remove the TOTP, the security keys, the
backup codes or a passkey, mint new backup codes, and remember a device that skips the factor. The MFA guide asked
hosts to put some of these behind `checkStepUp`; nothing enforced it, and nothing asked it of a passkey. Every one
of these calls now takes the caller's `session` and throws `AUTH_MFA_REQUIRED` unless it is the account's own, at
AAL 2, in the same tenant and still fresh; `meta.methods` names what the account holds, from `totp`, `backup-code`,
`webauthn` and `passkey`. An account with only a password changes its factors as before. Backup codes count by
themselves, so an account whose TOTP was removed needs a step-up until its codes go too.

**Nor does it mint an API key, link a provider or replace the password.** The same session could still create or
rotate an API key, which signs in without a second factor at all, link or unlink a provider login, through the flows
or `auth.identities` itself, and set a new password. Each now asks the same of it. `rotate` asks it of the key's
owner, before it revokes anything. `bulkCreate`'s `merge` links with no session, so it folds no login into an account
with a factor beside the password.

**A password reset asks the same of a passkey account.** `completePasswordReset` threw `AUTH_RECOVERY_REQUIRES_MFA`
only beside a TOTP or a WebAuthn-MFA key, so on an account secured by a passkey a mailed link alone replaced the
password. It now counts every factor beside the password, passkeys and backup codes included, and
`requestPasswordReset`'s `requiresMfa` agrees.

**A passkey steps a session up.** `completeStepUp` takes `{ method: 'passkey', passkey: { sessionId, response } }`,
begun with `beginProvider('passkey', { sessionId })`, so an account whose only factor is a passkey can step up to
change it. The passkey has to be the session identity's own and verify the user.

**TOTP can be replaced.** Enrolling again beside a confirmed TOTP was refused outright, and so was a TOTP beside a
security key. From a stepped-up session it now begins a replacement: the old TOTP keeps working until the new one
confirms, which retires it and mints fresh backup codes.

**Breaking: every factor change takes the session.** Pass the caller's resolved session, `null` without one:

- `auth.mfa`: `beginTotpEnrollment(id, accountName, session)`, `confirmTotpEnrollment(id, code, session)`,
  `removeTotp(id, session)`, `removeWebauthnMfa(id, session)`, `removeBackupCodes(id, session)` and
  `regenerateBackupCodes(id, session)`, and `session` in the options of `beginWebauthnMfaEnrollment` and
  `confirmWebauthnMfaEnrollment`.
- `auth.passkeys.revoke(id, credentialId, store, session)` and `revokeAll(id, store, session)`, and `session` in
  the input of `beginPasskeyRegistration` and `completePasskeyRegistration`.
- `RememberMeFacet.issue(id, session, opts)`.
- `auth.apiKeys.create(id, { name, scopes, session })` and `auth.apiKeys.rotate(keyId, session)`.
- `session` in the input of `flows.linkProvider` and `flows.unlinkProvider`. `allowLockout` lifts the last-way-in
  guard only.
- `auth.identities.link(id, link, session, ctx)`, `unlink(id, providerId, session, ctx)`, `linkMany(links, session,
  ctx)` and `unlinkMany(links, session, ctx)`. A batch leaves out each identity its session may not change.
- `auth.passwords.set(id, plaintext, store, session, ctx)`: the session comes before the tenant context, so a call
  that passed `{ tenantId }` fourth passes `null` before it. Sign-up and seed code passes `null`.

A call that throws `AUTH_MFA_REQUIRED` needs a step-up with one of its `meta.methods`, then the same call again; a
route that removes the TOTP and then its backup codes passes the same stepped-up session to both. `meta.methods` on
`AUTH_MFA_REQUIRED` and `AUTH_RECOVERY_REQUIRES_MFA` can now carry `backup-code` and `passkey`. A passkey account
that has lost its passkey can no longer reset its way back in, as a TOTP account already could not; recover it
through the store. An admin linking or unlinking a provider on someone else's account with a second factor goes
through the store too, `auth.cfg.stores.identities`, which runs neither the step-up nor the last-way-in guard and
emits no event.

**TOTP secrets are stored encrypted.** A TOTP secret is the second factor itself, and `beginTotpEnrollment` wrote
it to the credential row as it was, so whoever could read the database (a backup, a replica, a read-only injection)
could make every code for every enrolled account. `mfaProvider` now encrypts each secret under the `dataAtRest`
adapter it is given, bound to its identity, so a row copied onto another account opens nothing. After a key
rotation, a secret moves to the current key at its next good code.

**Breaking: `mfaProvider` needs a key.** Pass `dataAtRest`; without one, `createAuth` throws `AUTH_MISCONFIGURED`
at boot:

```ts
import { authAesGcmDataAtRest } from '@gentleduck/auth/core/dataAtRest'

mfaProvider({ dataAtRest: authAesGcmDataAtRest({ kid: 'k1', masterKey: Buffer.from(process.env.MFA_KEY ?? '', 'base64') }) })
```

Existing enrollments are not migrated. A secret stored before this release does not decrypt, so `verifyTotp` and a
`totp` step-up throw `AUTH_INVALID_PARAMETERS` for it instead of answering a wrong code. Its owner signs in with a
backup code, which the same challenge still takes, and enrolls again; an account with no backup code left needs its
`totp` row removed through the store. `new MfaFacet(store, events, cfg)` now requires `cfg`, and
`DEFAULT_MFA_CONFIG` is typed without `dataAtRest`. `@gentleduck/auth/test` adds `authTestDataAtRest()`, a key
drawn once per process, which `createTest` gives the provider unless `mfa.dataAtRest` replaces it.

**A call that names no tenant no longer reaches every tenant.** A tenant was a filter each caller had to
remember: a sign-in, a resolve, a session listing, an API key check or an orgs read that named none read every
tenant's rows. A tenanted app that forgot the tenant on one route signed a tenant's credential in to a session with
no tenant, accepted any tenant's session, or listed and revoked another tenant's sessions. Naming no tenant now
reaches only the records with no tenant, which in an app without tenants is every record, so such an app changes
nothing. `ALL_TENANTS`, from `@gentleduck/auth/core`, reaches every tenant; the engine uses it for its own work
across them, such as erasure, export and ending every session after a password reset.

**Breaking, for a tenanted app: name the tenant, or `ALL_TENANTS`.**

- `resolveSession` without `expectedTenantId`, `flows.impersonate` without `tenantId`, and the OIDC provider's
  `authorize(query, { headers }, { tenantId })` and `userinfo(headers, { tenantId })` without one accept only a
  session or token with no tenant.
- Every adapter's actor scope, Nest's `makeGuard` and `withGrpc` take `tenantId: (req) => string | undefined`,
  read on each request. Without it a tenant's session runs as nobody.
- The CSRF guards check the token of the session the cookie names, in whatever tenant, and take no tenant:
  `Csrf.GuardOptions.expectedTenantId` is removed. A guard told a tenant skipped the token for a session in any
  other. `resolveSession(req, { allTenants: true })` is the resolve they use; never authorise on it.
- `auth.sessions`, `auth.mfa`, `auth.apiKeys`, `auth.orgs` and `identities.exportAll` reach the tenant their
  context names: `{ tenantId }` for one, `ALL_TENANTS` for all.
- A token a flow mails in a tenant, for a password reset, an email verification or an account deletion and its
  undo, is redeemed in that tenant: pass the same `tenantId` to the `complete` call.
- A key created with a `tenantId` verifies, signs in and is exchanged only where that tenant is named;
  `m2m`'s `exchange` takes `tenantId`. `apiKeys.create` asks the step-up of the key's tenant.
- `withTenant`, `currentTenant` and `resolveTenant` are removed. No engine call read the tenant they bound.
- `AUTH_TENANT_SCOPE_VIOLATION` carries `asked: null` for a call that named no tenant.
- A store of your own follows the same rule: `{}` reaches only the rows with a null tenant, `{ tenantId }` that
  tenant's, and `{ allTenants: true }` every row. The shipped memory, Redis and Drizzle stores do.

**A provider link signs in only to the tenant it was made in.** Credentials and sessions carried a tenant and
provider links did not, so a login linked in one tenant signed its owner in to every other, and one Google account
could belong to only one person across all of them. A link now carries a `tenantId`. An OAuth sign-in finds only a
link in the tenant it names, and links or creates in that tenant, `onSignIn`'s helpers included. The same login can
be linked once in each tenant, to the same person or to different people.

**Breaking: provider links carry a tenant.**

- `Identities.ProviderLink` has `tenantId: string | null`, and the store's `find({ providerId, providerSub,
  tenantId })`, `link(id, link)` and `unlink(id, providerId, tenantId)` take it. A store of your own matches it with
  the provider and sub, `null` matching only `null`; the shipped memory and Drizzle stores do.
- `identities.getByProviderSub`, `create`, `bulkCreate`, `link` and `unlink` take the tenant context last, `{}` for
  none, and `flows.linkProvider` and `unlinkProvider` take `tenantId`. `exportAll` narrows the links to its context.
- Linking or unlinking asks the step-up of the link's tenant only, and `unlinkProvider` counts only the ways into
  that tenant.
- Drizzle: `auth_identity_providers` gains a nullable `tenant_id`, and both its uniques hold per tenant. Generate
  the migration with drizzle-kit.
- Existing links get no tenant, so they sign in only where no tenant is named. A tenanted app sets `tenant_id` on
  each, and inserts a copy for each further tenant the login should open.

**Ending an OIDC grant now ends every token it issued, of either kind.** `OidcOpRoot.token` denied a second
redemption of the same `authorization_code` and left the first redemption's tokens live, so whoever redeemed it
first kept a 30-day refresh grant and an hour-long access token off a 10-minute code (RFC 6749 4.1.2 asks for
both halves). The refresh family is now derived from the code, so a redemption that finds the code already
spent, unknown or expired revokes every token descended from it, however many rotations later. Access tokens
carry the family of their grant, so the same revocation reaches them, and so do the other three paths that end
a grant: a replayed refresh token, a subject since erased, and revoking a refresh token at `/revoke`
(RFC 7009 2.1). Revoking a single access token there still takes only that token, since one leaked token is not
a leaked grant.

**`auth_time` and `sid` reach the ID token, and survive a refresh.** An RP that asked for `max_age` had no way
to check the freshness it asked for: the OP enforced `max_age` and then minted an ID token with no `auth_time`
claim, which OIDC Core 3.1.3.6 requires of that response. `authorize` now answers `consent_required` with an
`auth_time` — when the person last presented a factor — to pass back to `completeConsent`, and mints the claim
on the paths that redirect straight to a code. Omitting it omits the claim rather than inventing a time nobody
measured. Both claims are stored against the grant, so a refreshed ID token repeats the sign-in it descends
from instead of reporting the refresh as a fresh authentication (OIDC Core 12.2). `at_hash` is deliberately
still absent: it is keyed to the signing algorithm's hash, which `signIdToken` hides, and a wrong `at_hash` is
worse than none.

**Breaking, for a hand-written OIDC OP store only.** The shipped memory and Drizzle stores are updated; a store
of your own needs three columns and one method. `oidc_codes` gains a nullable `auth_time`, `oidc_refresh_tokens`
gains `sid` and a nullable `auth_time`, and `oidc_access_tokens` gains a non-null `family_id` (index it) plus
`revokeFamily(family_id)`, which deletes every access token holding that family. Run
`bun run e2e:schema`-equivalent DDL for your dialect, or copy it from
`src/test/oidc-{pg,mysql,sqlite}-e2e-schema.sql`. Rows written before the upgrade read back with an empty `sid`
and a null `auth_time`, which omits both claims; grants predating the `family_id` column must be migrated with a
value or ended.

**`authBuildOidcDiscovery` refuses a `signingAlgs` list carrying `none`.** The document it builds is what an RP
reads to decide which signatures to accept, and `none` in that list tells it an unsigned ID token is acceptable
— the one answer OIDC Core 16.18 forbids. The union type already ruled it out at a call site a compiler reads,
but a list parsed from a config file or an environment variable reached the document unchecked. `none` in any
casing is now `AUTH_MISCONFIGURED` at build time. The default (`['HS256']`) and every real algorithm are
unaffected.

**A discovery document cannot stall the event loop.** `authFetchOidcDiscovery` trimmed the `issuer` it fetched with
a backtracking regex, quadratic over a run of slashes that does not end the string, so a 64 KB document held the
thread for about a second on every fetch, and a mismatch is never cached. The fetched and configured issuers, the
discovery prefix and the OP's issuer are now trimmed in one pass.

**Every production check reads `NODE_ENV`, and an unset one is production.** Each relaxation had a switch of
its own, and a deploy could run development pieces in production without setting any of them. `createAuth` ran
`strict()` for `NODE_ENV`, falling back to `development`, so a runtime that never set it skipped every
production check. The null captcha verifier, `MemoryDPoPNonceStore` and `MemoryIdempotency` refused only an
exact `production`. Three flags were refused nowhere: OIDC's `allowHttp`, OAuth's `stateCookie: { secure: false }`
and SAML's `allowReplay`, which lets a captured assertion sign in again until it expires. One rule now decides
all of them: `development` and `test` relax, and any other value, unset, empty, `staging` or `Production`
included, is production. Outside production, webhooks, a captcha mock and an OIDC issuer reach plain http and
`localhost`; private, link-local and metadata hosts stay refused everywhere. `createAuth({ webhooks })` attaches
a deliverer to the engine's bus.

**Breaking: development needs `NODE_ENV=development`.**

- With `NODE_ENV` unset, `createAuth` refuses the memory store and limiter, an http `baseUrl` and a missing
  `lockout` listener, and the in-process pieces refuse to be built. Set `NODE_ENV=development` for local runs;
  Vitest, Jest and `bun test` set `test` themselves.
- Cookies are Secure in production and not outside it, where a `__Host-` or `__Secure-` prefix is dropped from
  the name: the defaults become `duck-sid`, `duck-csrf`, `duck-oauth` and `duck-refresh`. `sameSite: 'none'`
  stays Secure everywhere. Read a name back with `transport.csrfCookieName` or the new `jwt.refreshCookieName`.
- Removed: `CookieTransport`'s `secure` option and getter, `OAuth.StateCookie.secure`, `allowStateReplay`,
  SAML's `allowReplay`, `allowHttp` on `authBuildOidcDiscovery`, `authFetchOidcDiscovery` and `createOidcOP`,
  `allowInsecure` on `WebhookDeliverer`, captcha's `allowInsecureEndpoint`, and
  `development` on `AuthNullCaptchaVerifier`, `MemoryDPoPNonceStore` and `MemoryIdempotency`.
- Production requires an OAuth `nonceStore` and a SAML `replayStore` at construction.
- The OIDC OP's five in-memory stores refuse production as they are built, so `createOidcOP` there needs every
  store in `stores`. One left out fell back to memory, where a `/revoke` landing on another instance revoked
  nothing and a restart forgot every client and grant.
- `createAuth`'s `strict` takes only `false`, which defers the checks to `auth.strict()`; an environment name
  is refused. `auth.strict()` takes no `env`: call `auth.strict()` or `auth.strict({ compliance })`.

**Breaking: `createAuth`'s default session cookie is `__Host-duck-sid`.** With no `transport` it was `duck-sid`,
a name any subdomain can set, so a sibling app could sign the browser into a session of its choosing;
`cookieTransport()` already defaulted to the prefixed name. In production a session under the old name reads as
signed out once, and its owner signs in again. Outside production the name is still `duck-sid`. To keep the old
name, pass `transport: cookieTransport({ name: 'duck-sid' })`.
