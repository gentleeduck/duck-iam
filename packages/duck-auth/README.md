<p align="center">
  <img src="./public/logo-dark.svg" alt="@gentleduck/auth" width="120"/>
</p>

<h1 align="center">@gentleduck/auth</h1>

<p align="center">
  Faceted, framework-agnostic, transport-pluggable authentication for TypeScript. Pairs with <a href="https://www.npmjs.com/package/@gentleduck/iam"><code>@gentleduck/iam</code></a> for authorization.
</p>

<p align="center">
  <a href="./LICENSE">MIT</a> -
  <a href="./CHANGELOG.md">Changelog</a> -
  <a href="./SECURITY.md">Security</a> -
  <a href="https://gentleduck.org/duck-auth">Docs</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@gentleduck/auth"><img src="https://img.shields.io/npm/v/@gentleduck/auth.svg" alt="npm"/></a>
  <a href="https://www.npmjs.com/package/@gentleduck/auth"><img src="https://img.shields.io/npm/dm/@gentleduck/auth.svg" alt="downloads"/></a>
  <a href="./LICENSE"><img src="https://img.shields.io/npm/l/@gentleduck/auth.svg" alt="MIT"/></a>
</p>

---

Every TypeScript auth library makes you choose framework lock-in (NextAuth, Auth.js), a hosted control plane (Clerk, WorkOS, Stytch), or DIY-on-Lucia + passport + your own glue. `@gentleduck/auth` is the third option, but unified: framework-agnostic core, batteries-included adapters, no hosted plane. Wire it into Express, Hono, Next.js, Fastify, Koa, NestJS, Elysia, gRPC, or your own router with one adapter import.

Zero hosted dependencies. Tree-shakeable subpath exports. Lazy peer deps for the heavy bits (argon2, simplewebauthn, ioredis, nodemailer).

## Install

```bash
npm install @gentleduck/auth
# or
bun add @gentleduck/auth
```

Optional peer dependencies (install only what you wire):

| Peer | When you need it |
|---|---|
| `@node-rs/argon2` | Argon2id password hashing (FIPS / HIPAA presets) |
| `@simplewebauthn/server` | Passkey / WebAuthn-MFA |
| `ioredis` or `@upstash/redis` | Redis-backed session / idempotency / limiter / events / DPoP-nonce stores |
| `nodemailer` (or compatible) | SMTP channel |
| `drizzle-orm` + driver | Drizzle adapter (pg / mysql / sqlite) |
| `@prisma/client` | Prisma adapter |
| `node-saml` | SAML 2.0 SP |

## Quick start

```typescript
import { createAuth } from '@gentleduck/auth/core/config'
import { MemoryAuthAdapter } from '@gentleduck/auth/adapters/memory'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { password } from '@gentleduck/auth/providers/password'

const storage = new MemoryAuthAdapter()

export const auth = createAuth({
  baseUrl: 'http://localhost:3000',
  storage,
  limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
  providers: [
    (a) => password({
      findIdentityByEmail: (email) => storage.identities.findByEmail(email, {}),
      passwords: a.passwords,
    }),
  ],
})

const identity = await auth.identities.create({ profile: { email: 'a@x.com' } })
await auth.passwords.set(identity.id, 'correct-horse-battery')

const result = await auth.flows.signIn({
  providerId: 'password',
  input: { email: 'a@x.com', password: 'correct-horse-battery' },
})
// result.session, result.sid, result.intents[]
```

`createAuth` is the factory that wires the 14 facets, picks sane defaults (CookieTransport, AuthScryptHasher, AuthInMemoryEvents), and registers the providers you pass. For full control, instantiate `AuthEngine` directly - both APIs accept the same primitives.

## Or scaffold it via the CLI

```bash
bunx @gentleduck/auth init src/auth                # quickstart
bunx @gentleduck/auth init src/auth --production   # Redis + JWT + Argon2id
bunx @gentleduck/auth doctor                       # run AuthEngine.strict()
bunx @gentleduck/auth keys generate hs256          # mint a JWT signing secret
bunx @gentleduck/auth keys generate ec256          # mint an ES256 keypair (DPoP)
```

## Architecture

`AuthEngine` is the 14-facet root: every state-changing operation lives behind one named facet so adapters, transports, and providers compose without back-channel coupling.

| Facet | Owns |
|---|---|
| `identities` | profile CRUD, link/unlink, soft-delete + grace-period restore, GDPR export, bulk import |
| `sessions` | rotateOrCreate (single privilege-changing API), getBySid, revoke, revokeAllForIdentity, gc |
| `credentials` | password / api-key / oauth / passkey / recovery / totp / webauthn-mfa rows; CAS rotation |
| `passwords` | strength + cap validation, constant-time verify, needsRehash + auto-rehash, common-list reject |
| `mfa` | TOTP enrollment + verify, backup-code mint/verify, WebAuthn-MFA, AAL3 detection |
| `apiKeys` | mint / list / rotate / revoke / verify + scope checks, tenant-bound issuance |
| `flows` | signIn / signOut / signUp (multi-stage) / password-reset / email-verification / account-deletion / linkProvider / unlinkProvider / impersonate / step-up / step-down |
| `csrf` | double-submit + origin-only + sec-fetch-site gates, `__Host-` cookie |
| `idempotency` | per-(identity, key) tombstone + poll, NaN-bypass defense on TTL |
| `webhooks` | HMAC + timestamp + tolerance, retry w/ backoff, dead-letter, SSRF-guarded URLs |
| `events` | typed bus, lockout / signin.success / signin.failed / suspicious / session.revoked / mfa.removed |
| `hijack` | IP / UA drift detection + step-up / rotate / revoke reaction policy |
| `anomaly` | pluggable detectors (impossible-travel, device-fingerprint), composition + decision ladder |
| `orgs` | org + membership CRUD, role sanitisation, multi-tenant guard |

Plus `m2m` (`client_credentials` OAuth2 grant), `compliance` (FIPS / HIPAA / SOC2 presets), `plugin` (named install + facet extension), and `audit` (admin-mutation hook with redaction).

## Providers

| Path | What |
|---|---|
| `@gentleduck/auth/providers/password` | Email + password |
| `@gentleduck/auth/providers/magic-link` | Passwordless one-time link |
| `@gentleduck/auth/providers/passkey` | WebAuthn passkey (lazy peerDep on `@simplewebauthn/server`) |
| `@gentleduck/auth/providers/api-key` | Long-lived bearer keys via `ApiKeysFacet` |
| `@gentleduck/auth/providers/oauth/google` | Google OAuth (PKCE + nonce) |
| `@gentleduck/auth/providers/oauth/github` | GitHub OAuth (PKCE + state) |
| `@gentleduck/auth/providers/oauth/microsoft` | Microsoft / Entra ID OAuth |
| `@gentleduck/auth/providers/oauth/discord` | Discord OAuth |
| `@gentleduck/auth/providers/oauth/linkedin` | LinkedIn OAuth |
| `@gentleduck/auth/providers/oauth/apple` | Sign in with Apple |
| `@gentleduck/auth/providers/oauth/core` | Generic OAuth2 / OIDC client base. Build your own per-IdP wrapper |
| `@gentleduck/auth/providers/saml` | Wrapper over `@node-saml/node-saml` (lazy peerDep): SP-initiated + IdP-initiated SSO, SP metadata XML generation, Single Logout (SP- and IdP-initiated) |

## Transports

```typescript
import {
  CookieTransport,    // __Host- prefix + HttpOnly + SameSite=Lax (default)
  BearerTransport,    // opaque tokens in Authorization header
  JwtTransport,       // HS256 / RS256 / ES256 / EdDSA + JWKS rotation
  CompositeTransport, // chain multiple transports
} from '@gentleduck/auth/core/transport'

import {
  DPoPVerifier,
  MemoryDPoPNonceStore,
  computeJwkThumbprint,
  bindPayloadToDPoP,
} from '@gentleduck/auth/core/transport/dpop' // RFC 9449
```

## Storage adapters

```typescript
import { MemoryAuthAdapter } from '@gentleduck/auth/adapters/memory'
import { drizzlePgStorage }  from '@gentleduck/auth/adapters/drizzle/pg'
import { drizzleMysqlStorage } from '@gentleduck/auth/adapters/drizzle/mysql'
import { drizzleSqliteStorage } from '@gentleduck/auth/adapters/drizzle/sqlite'
import { createSqlStores } from '@gentleduck/auth/adapters/sql' // build your own bridge
import {
  RedisSessionStore,
  RedisIdempotencyStore,
  RedisLimiter,
  RedisEvents,
  RedisDPoPNonceStore,
  FakeRedis, // in-tree, for tests
} from '@gentleduck/auth/adapters/redis'
```

## Transactions

Every SQL-backed write and read can run on a transaction you own. `withTransaction(tx)`
returns a view of the engine bound to your transaction handle; the handle is opaque to
duck-auth and is handed straight back to your adapter.

```typescript
let pending
await db.transaction(async (tx) => {
  const auth = engine.withTransaction(tx)
  await auth.identities.softDelete(identityId)
  await auth.sessions.revokeAllForIdentity(identityId)
  await tx.delete(users).where(eq(users.id, identityId))
  pending = auth.pending
})
await pending.flush()   // publish the events only once the commit landed
```

Nested calls inherit it: `auth.flows.completeAccountDeletion()` reaches
`identities.softDelete`, `sessions.revokeAllForIdentity` and `credentials.delete`, and all
three land on your transaction. Reads are bound too, so a read inside the transaction sees
that transaction's own uncommitted writes.

**Events do not fire inside a transaction.** They buffer in `pending` and publish when you
call `flush()`. A rolled-back delete therefore never appears in the audit trail as a
completed one. Call `flush()` after your commit; call `pending.discard()` if you rolled
back deliberately and want the buffer dropped. `pending.peek()` inspects the buffer without
draining it.

### What is and isn't transactional

| Surface | In a transaction? | On rollback |
|---|---|---|
| `identities`, `sessions`, `credentials` - writes and reads | yes | undone |
| `flows.*`, including nested facet calls | yes | undone |
| `mfa`, `apiKeys`, `passwords` credential writes | yes | undone |
| `orgs` | interface ready; no shipped SQL adapter | n/a |
| events | buffered in `pending` | never published |
| channel sends (verification / reset mail) | **no - sent immediately** | mail already delivered |
| `limiter` counters | **no** | token stays consumed |
| `idempotency` records | **no** | record stands |
| `hijack` / `anomaly` scoring | **no** | scores stand |

The last four are guards: they decide *whether* to do the work, they write nothing to SQL,
and they are not reachable on the bound view at all - use `engine.limiter`,
`engine.idempotency` and friends outside the transaction. A flow that sends mail should be
called outside a transaction, or split so the send happens after the commit; no rollback
can retract a delivered email.

**An engine with no transaction supplied behaves exactly as before:** writes go to its own
connection and events publish immediately.

### Adapter support

`withTransaction` needs a store whose adapter implements `withClient`. The drizzle pg,
mysql and sqlite adapters do; so does any bridge built with `createSqlStores`. Memory,
redis and valkey do not - they cannot join a SQL transaction - and `withTransaction` throws
`AUTH_MISCONFIGURED` naming the store rather than silently leaving it outside your
transaction.

### Batch writes

Batch forms take a list and report per-row outcomes instead of collapsing to `void`:

```typescript
const result = await auth.identities.updateProfileMany([
  { id: a, patch: { displayName: 'A' }, expectedVersion: 3 },
  { id: b, patch: { displayName: 'B' }, expectedVersion: 7 },
])
result.outcomes  // [{ id: a, ok: true, value: … }, { id: b, ok: false, reason: 'stale-write' }]
result.applied   // 1
```

Available on `identities` (`softDeleteMany`, `restoreMany`, `eraseMany`, `updateProfileMany`,
`linkMany`, `unlinkMany`), `sessions` (`revokeAllForIdentities`, `revokeByHashes`) and the
credential store (`auth.stores.credentials.deleteByIdentities`). Each collapses to one
statement per table where the adapter can express it and loops otherwise, so every adapter
supports every batch form.

A **hard** failure - a constraint violation - throws and aborts your transaction, so one
bad row rolls the whole batch back. A **soft** failure - a lost optimistic-lock race, a
missing row - is reported per row and does not throw.

## Server adapters

```typescript
// Express
import { mountSignIn, mountSignOut, mountProviderBegin } from '@gentleduck/auth/server/express'
app.post('/auth/signin', mountSignIn(auth))

// Hono
import { mount } from '@gentleduck/auth/server/hono'
mount(app, auth, { prefix: '/auth' })

// Next.js App Router
import { nextSignIn, nextSignOut } from '@gentleduck/auth/server/next'
export const POST = nextSignIn(auth)

// Fastify, Koa, NestJS, Elysia, gRPC
import { fastifySignIn } from '@gentleduck/auth/server/fastify'
import { koaSignIn }     from '@gentleduck/auth/server/koa'
import { nestSignIn }    from '@gentleduck/auth/server/nestjs'
import { elysiaSignIn }  from '@gentleduck/auth/server/elysia'
import { authGrpcService } from '@gentleduck/auth/server/grpc'

// Generic Web-Fetch executor (Cloudflare Workers, Bun, Deno)
import { executeIntents, parseSignInBody } from '@gentleduck/auth/server/generic'
```

## Channels

| Path | What |
|---|---|
| `@gentleduck/auth/channels/console` | Console / Noop / Test channels (dev + test) |
| `@gentleduck/auth/channels/smtp` | Nodemailer-compatible SMTP relay |
| `@gentleduck/auth/channels/resend` | Resend HTTP API |
| `@gentleduck/auth/channels/twilio` | Twilio SMS |
| `@gentleduck/auth/channels/webpush` | Web Push (`web-push`) |
| `@gentleduck/auth/channels/ses` | AWS SES (`@aws-sdk/client-sesv2`) |

## Client libraries

```typescript
// React - <Provider> + useSession / useSignIn / useSignOut
import { createAuthClient } from '@gentleduck/auth/client/react'

// Vue, Solid, Svelte - parallel APIs
import { createAuthClient as createVueAuth }    from '@gentleduck/auth/client/vue'
import { createAuthClient as createSolidAuth }  from '@gentleduck/auth/client/solid'
import { createAuthClient as createSvelteAuth } from '@gentleduck/auth/client/svelte'

// Vanilla - promise-based signIn / signOut / resolveSession
import { createAuthClient } from '@gentleduck/auth/client/vanilla'
```

## Captcha verifiers

```typescript
import { turnstileVerifier } from '@gentleduck/auth/captcha/turnstile'
import { hcaptchaVerifier }  from '@gentleduck/auth/captcha/hcaptcha'
import { recaptchaVerifier } from '@gentleduck/auth/captcha/recaptcha'
```

## Tooling

| Path | What |
|---|---|
| `@gentleduck/auth/cli` | `duck-auth init` / `doctor` / `keys generate` |
| `@gentleduck/auth/openapi` | `buildOpenApiSpec` + `renderOpenApiYaml` for the auth surface |
| `@gentleduck/auth/oidc` | OIDC discovery-doc + JWKS helper |
| `@gentleduck/auth/oidc/op` | Full OAuth2/OIDC OP: `/authorize` (code + S256 PKCE), `/token` (auth_code + refresh, family-rotated), `/userinfo`, `/introspect`, `/revoke`, `/register` (RFC 7591 Dynamic Client Registration) |
| `@gentleduck/auth/oidc/op/drizzle/pg` | Postgres Drizzle stores for the OIDC OP (5 tables, GC helper) |
| `@gentleduck/auth/oidc/op/drizzle/sqlite` | SQLite Drizzle stores for the OIDC OP |
| `@gentleduck/auth/oidc/op/drizzle/mysql` | MySQL Drizzle stores for the OIDC OP |
| `@gentleduck/auth/i18n` | Message catalogue + Lingui adapter |
| `@gentleduck/auth/telemetry` | OpenTelemetry metrics instrumentation |

## Production primitives

- **`AuthEngine.strict({ env: 'production' })`** - boot-time validation: rejects `secure: false` cookie transport, `NoopLimiter`, memory stores, missing `lockout` listener, non-HTTPS `baseUrl`
- **`JwtTransport.rotateSignKey()` + `retireVerifyKey(kid)`** - zero-downtime JWKS rotation with overlap window
- **`auth.compliance.applyPreset('soc2' | 'hipaa' | 'fips')`** - tightens password / session / MFA / data-at-rest settings to the named regulatory floor
- **`auth.webhooks`** - HMAC body + timestamp + freshness tolerance, exponential backoff, dead-letter sink, SSRF guard on endpoint URLs, `redirect: 'error'` on dispatch
- **`auth.hijack` + `auth.anomaly`** - drift detection, decision ladder (allow / step-up / deny), pluggable signals
- **`auth.idempotency`** - per-(identity, key) tombstone + poll for replay-safe mutating routes
- **Refresh-token reuse detection** (RFC 6749 §10.4) on OAuth refresh families
- **DPoP** (RFC 9449) - proof-of-possession on bearer tokens with `ath` binding and server nonce
- **Tenant boundary**: every adapter respects `ctx.tenantId`; M2M + api-key providers refuse cross-tenant identification

## Security posture

`AuthEngine.strict()` runs every production-grade gate before boot.

See [`SECURITY.md`](./SECURITY.md) for the STRIDE / OWASP ASVS mapping of every threat the library mitigates and every threat the host app must own.

## Module sizes (gzipped)

| Module | Size |
|--------|------|
| Core `AuthEngine` (typical import) | ~22 KB |
| Each transport | 2 - 6 KB |
| Each provider | 1.5 - 8 KB |
| Each adapter | 2 - 9 KB |
| Each server middleware | 2 - 4 KB |
| Each client library | 1.5 - 2.5 KB |
| Each channel | 1 - 3 KB |
| CLI | 12 KB (binary, not imported by app) |

Real deployments importing only what they wire end up at 25 - 60 KB total. The "import everything" worst case (`import * from '@gentleduck/auth'`) is not the intended usage.

## Docs

- Site: [gentleduck.org/duck-auth](https://gentleduck.org/duck-auth)
- Reference app: [`apps/duck-auth-demo`](https://github.com/gentleeduck/duck-iam/tree/main/apps/duck-auth-demo) - every flow exercised end-to-end
- Sibling repos: [`@gentleduck/iam`](https://www.npmjs.com/package/@gentleduck/iam), [`@gentleduck/ui`](https://github.com/gentleeduck/duck-ui), [`@gentleduck/upload`](https://github.com/gentleeduck/duck-upload), [`@gentleduck/md`](https://github.com/gentleeduck/duck-md)

## Contributing

PR checklist + style notes in the repo's [`CONTRIBUTING.md`](https://github.com/gentleeduck/duck-iam/blob/main/CONTRIBUTING.md).
Security disclosures: [`SECURITY.md`](./SECURITY.md).

## License

MIT. See [`LICENSE`](./LICENSE).
