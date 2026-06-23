# duck-auth Setup Guide

Full setup for `@gentleduck/auth` — sessions, auth providers, OIDC OP, server adapters.

---

## Install

```bash
bun add @gentleduck/auth
# optional peer deps based on what you use
bun add drizzle-orm pg          # drizzle-pg adapter
bun add ioredis                 # redis adapter / limiter
bun add resend                  # resend email channel
bun add argon2                  # argon2id hasher (prod)
```

---

## 1. Core Setup (`createAuth`)

`createAuth` is the primary entry point. Returns a wired `AuthEngine`.

```ts
// src/auth.ts
import { createAuth } from '@gentleduck/auth/core/config'
import { authDrizzlePgStorage } from '@gentleduck/auth/adapters/drizzle/pg'
import { AuthRedisLimiter } from '@gentleduck/auth/adapters/redis'
import { AuthArgon2idHasher } from '@gentleduck/auth/core/password/argon2'
import { AuthCookieTransport } from '@gentleduck/auth/core/transport'
import { AuthResendChannel } from '@gentleduck/auth/channels/resend'
import { authPassword } from '@gentleduck/auth/providers/password'
import { authMagicLink } from '@gentleduck/auth/providers/magic-link'
import { authGoogle } from '@gentleduck/auth/providers/oauth/google'
import { authGithub } from '@gentleduck/auth/providers/oauth/github'
import { db } from './db'         // your drizzle db instance
import { redis } from './redis'   // your ioredis instance
import { Resend } from 'resend'

interface Profile {
  email: string
  name?: string
  avatarUrl?: string
}

export const auth = createAuth<Profile>({
  baseUrl: process.env.APP_URL!,   // e.g. https://app.example.com

  // --- storage ---
  storage: authDrizzlePgStorage<Profile>(db),

  // --- transport ---
  // Default: AuthCookieTransport({ name: '__Host-duck-sid' })
  // Explicit for custom cookie name or Bearer:
  transport: new AuthCookieTransport({ name: 'duck-sid' }),

  // --- security ---
  hasher: new AuthArgon2idHasher(),
  limiter: new AuthRedisLimiter({ redis, max: 10, windowMs: 60_000 }),

  // --- delivery channels ---
  channels: {
    email: new AuthResendChannel({
      client: new Resend(process.env.RESEND_API_KEY!),
      from: 'auth@example.com',
    }),
  },

  // --- providers ---
  providers: [
    // email + password
    authPassword<Profile>({
      findIdentityByEmail: (email) => db.query.authIdentitiesTable.findFirst({...}),
      passwords: null as any, // injected automatically by createAuth
    }),

    // magic link (email OTP)
    authMagicLink<Profile>({ autoCreateIdentity: true }),

    // OAuth
    authGoogle<Profile>({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      redirectUri: `${process.env.APP_URL}/auth/callback/google`,
    }),
    authGithub<Profile>({
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      redirectUri: `${process.env.APP_URL}/auth/callback/github`,
    }),
  ],

  // --- session config ---
  session: {
    ttlMs: 7 * 24 * 60 * 60 * 1000,          // 7 days sliding
    absoluteTtlMs: 30 * 24 * 60 * 60 * 1000, // 30 days hard
    freshnessMs: 5 * 60 * 1000,               // re-check store every 5m
  },

  // --- enforce production rules at boot ---
  strict: process.env.NODE_ENV === 'production' ? 'production' : 'development',
})
```

> **Tip — `strict: 'production'`** throws at startup if you forgot a real limiter,
> left a memory adapter wired, or have `secure: false` on your cookie transport.
> Zero runtime cost — it only runs once.

---

## 2. Storage Adapters

### Memory (dev / tests only)

```ts
import { authMemoryStorage } from '@gentleduck/auth/adapters/memory'

storage: authMemoryStorage()
```

### Drizzle — PostgreSQL

```ts
import { authDrizzlePgStorage, authIdentitiesTable, authCredentialsTable, authSessionsTable } from '@gentleduck/auth/adapters/drizzle/pg'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const db = drizzle(pool)

// Run migrations — tables are exported for use in your schema
storage: authDrizzlePgStorage<Profile>(db)
```

Schema tables to add to your Drizzle schema:

```ts
// schema.ts
export { authIdentitiesTable, authCredentialsTable, authSessionsTable } from '@gentleduck/auth/adapters/drizzle/pg'
```

### Drizzle — SQLite / MySQL

```ts
import { authDrizzleSqliteStorage } from '@gentleduck/auth/adapters/drizzle/sqlite'
import { authDrizzleMysqlStorage } from '@gentleduck/auth/adapters/drizzle/mysql'
```

### `orgs` store — what it is and where to get it

`authDrizzlePgStorage` (and the other SQL adapters) do **not** include an `orgs` store.
`storage.orgs` is optional; omit it unless your app uses org-scoped sessions or duck-iam org scopes.

When you do need it, implement `AuthOrg.IStore<OrgMeta>` yourself against your own orgs table
and pass it into `createAuth`:

```ts
import type { AuthOrg } from '@gentleduck/auth/core/types'
import { orgsTable } from './schema'  // your own table
import { eq } from 'drizzle-orm'

const orgStore: AuthOrg.IStore<{ plan: string }> = {
  async findById(id, ctx) {
    const rows = await db.select().from(orgsTable).where(eq(orgsTable.id, id)).limit(1)
    return rows[0] ?? null
  },
  async listForIdentity(identityId, ctx) {
    // join your memberships table → orgs
    return []
  },
  async listMembers(orgId, ctx) {
    return []
  },
  async addMember(orgId, identityId, role, ctx) {
    // insert into memberships
  },
  async updateMember(orgId, identityId, patch, ctx) {},
  async removeMember(orgId, identityId, ctx) {},
}

export const auth = createAuth<Profile, string, { plan: string }>({
  storage: {
    ...authDrizzlePgStorage<Profile>(db),
    orgs: orgStore,
  },
  // ...
})
```

**When using duck-iam in the same project**: the IAM `scope` (e.g. `'org:acme'`) is the canonical
identifier for an org across both packages. Use the same org ID string in both:
- `engine.admin.assignRole(userId, 'editor', 'org:acme')` — IAM side
- `auth.orgs.addMember('org:acme', userId, 'editor')` — auth side

The two stores are independent; duck-iam does not read from `auth.stores.orgs` and vice versa.
Share the same database table if you want a single source of truth.

---

## 3. Transports

| Transport | Use case |
|---|---|
| `AuthCookieTransport` | Web apps (default) |
| `AuthBearerTransport` | APIs / mobile |
| `AuthCompositeTransport` | Cookie + Bearer simultaneously |
| `AuthJwtTransport` | Stateless JWT sessions |

```ts
import { AuthBearerTransport, AuthCompositeTransport } from '@gentleduck/auth/core/transport'

// API: read token from Authorization: Bearer <token>
transport: new AuthBearerTransport()

// Both cookie + bearer (SPA + API on same auth instance)
transport: new AuthCompositeTransport([
  new AuthCookieTransport({ name: 'duck-sid' }),
  new AuthBearerTransport(),
])
```

---

## 4. Providers

### Password

```ts
import { authPassword } from '@gentleduck/auth/providers/password'

authPassword<Profile>({
  findIdentityByEmail: async (email) => {
    // return { id: string } | null
    return db.query.users.findFirst({ where: eq(users.email, email) })
  },
  passwords: auth.passwords,   // bind after createAuth if constructing AuthEngine directly
  autoRehash: true,            // re-hash on login when algorithm changes
})
```

Sign-in input shape: `{ email: string; password: string }`.

### Magic Link

```ts
import { authMagicLink } from '@gentleduck/auth/providers/magic-link'

authMagicLink<Profile>({
  autoCreateIdentity: true,         // create account on first magic-link verify
  ttlMs: 15 * 60 * 1000,           // link expires in 15m
})
```

Requires `channels.email` to be configured in `createAuth`.

### OAuth — Google / GitHub / Discord / Microsoft / Apple / LinkedIn

```ts
import { authGoogle } from '@gentleduck/auth/providers/oauth/google'
import { authGithub } from '@gentleduck/auth/providers/oauth/github'
import { authDiscord } from '@gentleduck/auth/providers/oauth/discord'
import { authMicrosoft } from '@gentleduck/auth/providers/oauth/microsoft'
import { authApple } from '@gentleduck/auth/providers/oauth/apple'
import { authLinkedin } from '@gentleduck/auth/providers/oauth/linkedin'

authGoogle<Profile>({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: `${process.env.APP_URL}/auth/callback/google`,
  // mapProfile: (raw) => ({ email: raw.email, name: raw.name })
})
```

### Passkey (WebAuthn)

```ts
import { authPasskey } from '@gentleduck/auth/providers/passkey'

authPasskey<Profile>({
  rpId: 'example.com',
  rpName: 'My App',
  origin: process.env.APP_URL!,
})
```

### API Keys

```ts
import { authApiKey } from '@gentleduck/auth/providers/api-key'

authApiKey<Profile>()
```

Issue keys: `auth.apiKeys.issue(identityId)`.  
Verify: included in `auth.resolveSession()` when using `AuthBearerTransport`.

### SAML

```ts
import { authSamlProvider } from '@gentleduck/auth/providers/saml'

authSamlProvider<Profile>({
  entryPoint: 'https://idp.example.com/sso/saml',
  issuer: process.env.APP_URL!,
  cert: process.env.IDP_CERT!,
})
```

---

## 5. Server Adapters

Pick one. All expose the same `signIn`, `signOut`, `session`, `beginProvider`, `callback` handlers.

### Hono

```ts
import { Hono } from 'hono'
import {
  authHonoSignIn,
  authHonoSignOut,
  authHonoSession,
  authHonoBeginProvider,
  authHonoCallback,
} from '@gentleduck/auth/server/hono'
import { auth } from './auth'

const app = new Hono()

app.post('/auth/signin',               authHonoSignIn(auth))
app.post('/auth/signout',              authHonoSignOut(auth))
app.get('/auth/session',               authHonoSession(auth))
app.post('/auth/providers/:id/begin',  authHonoBeginProvider(auth))
app.get('/auth/providers/:id/callback', authHonoCallback(auth))
```

### Express

```ts
import express from 'express'
import {
  authExpressSignIn,
  authExpressSignOut,
  authExpressSession,
} from '@gentleduck/auth/server/express'
import { auth } from './auth'

const router = express.Router()
router.post('/auth/signin',  authExpressSignIn(auth))
router.post('/auth/signout', authExpressSignOut(auth))
router.get('/auth/session',  authExpressSession(auth))
```

### Next.js

```ts
// app/api/auth/[...auth]/route.ts
import { authNextSignIn, authNextSignOut, authNextSession } from '@gentleduck/auth/server/next'
import { auth } from '@/lib/auth'

export const POST = authNextSignIn(auth)
// or mount all handlers:
export { authNextSignIn as POST, authNextSession as GET }
```

### Fastify / Koa / NestJS / Elysia

```ts
import { authFastifySignIn } from '@gentleduck/auth/server/fastify'
import { authKoaSignIn }     from '@gentleduck/auth/server/koa'
import { authElysiaSignIn }  from '@gentleduck/auth/server/elysia'
```

---

## 6. Session Resolution

```ts
const result = await auth.resolveSession({ headers: request.headers })

if (!result) {
  // no token or expired session
  return Response.redirect('/login')
}

const { session, identity } = result
console.log(session.identityId)   // string
console.log(session.aal)          // 1 (password) | 2 (MFA)
console.log(identity?.profile)    // Profile shape
```

With anomaly detection:

```ts
const result = await auth.resolveSession({ headers: request.headers }, {
  requestSnapshot: {
    ip: request.ip,
    userAgent: request.headers.get('user-agent') ?? '',
    country: request.cf?.country,
  },
})

if (result?.anomaly?.decision === 'deny') return Response.redirect('/login')
if (result?.anomaly?.decision === 'step-up') return Response.redirect('/mfa')
```

---

## 7. MFA

```ts
// Enroll TOTP
const { uri, secret } = await auth.mfa.enrollTotp(identityId)
// show `uri` as a QR code, store `secret` for verification

// Verify TOTP
await auth.mfa.verifyTotp(identityId, totpCode)

// Backup codes
const codes = await auth.mfa.enrollBackupCodes(identityId)
await auth.mfa.verifyBackupCode(identityId, code)
```

---

## 8. Events

```ts
auth.events.on('signin.success', ({ session }) => {
  console.log('signed in', session.identityId)
})

auth.events.on('signin.failed', ({ reason }) => {
  auditLog.write({ event: 'signin.failed', reason })
})

auth.events.on('lockout', ({ key }) => {
  alertOncall(`rate-limit lockout: ${key}`)
})
```

> **Prod requirement**: `strict('production')` throws if no `lockout` listener is registered.

---

## 9. OIDC Provider (full OP)

duck-auth ships a full OIDC Authorization Server (OP).

```ts
import { AuthOidcOpRoot } from '@gentleduck/auth/oidc/op'
import {
  AuthMemoryClientStore,
  AuthMemoryCodeStore,
  AuthMemoryAccessTokenStore,
  AuthMemoryRefreshTokenStore,
  AuthMemoryConsentStore,
} from '@gentleduck/auth/oidc/op'
import { authBuildOidcDiscovery } from '@gentleduck/auth/oidc'
import { AuthJwtTransport } from '@gentleduck/auth/core/transport'
import { auth } from './auth'

// 1. JWT transport for signing id_tokens
const jwtTransport = new AuthJwtTransport({
  secret: process.env.JWT_SECRET!,
  ttlSeconds: 3600,
})

// 2. Stores — swap for Redis/Drizzle in prod
const clients      = new AuthMemoryClientStore()
const codes        = new AuthMemoryCodeStore()
const accessTokens = new AuthMemoryAccessTokenStore()
const refreshTokens = new AuthMemoryRefreshTokenStore()
const consents     = new AuthMemoryConsentStore()

// 3. Wire the OP
const op = new AuthOidcOpRoot(
  {
    issuer: process.env.APP_URL!,
    supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
  },
  {
    auth,
    clients,
    codes,
    accessTokens,
    refreshTokens,
    consents,
    signIdToken: (payload) => jwtTransport.sign(payload),
  },
)

// 4. Register a client
await clients.insert({
  client_id: 'my-spa',
  client_secret: null,       // null = public PKCE-only client
  redirect_uris: ['https://app.example.com/callback'],
  grant_types: ['authorization_code'],
  response_types: ['code'],
})

// 5. Mount endpoints (Hono example)
import { Hono } from 'hono'
const oidc = new Hono()

// Discovery
const { discovery, jwks } = authBuildOidcRoutes({
  config: { issuer: process.env.APP_URL!, allowHttp: false },
  transport: jwtTransport,
})
oidc.get('/.well-known/openid-configuration', (c) => c.json(discovery))
oidc.get('/.well-known/jwks.json',            (c) => c.json(jwks))

// OIDC endpoints — host renders authorize UI, calls op methods
oidc.get('/authorize', async (c) => {
  const params = Object.fromEntries(new URL(c.req.url).searchParams)
  const result = await op.authorize(params)
  if (result.type === 'error')    return c.json(result.error, 400)
  if (result.type === 'redirect') return c.redirect(result.redirectUri)
  // result.type === 'consent' → render consent page
  return c.html('<form>...</form>')
})

oidc.post('/token', async (c) => {
  const body = await c.req.parseBody()
  const authHeader = c.req.header('authorization') ?? ''
  const result = await op.token(Object.fromEntries(Object.entries(body)), authHeader)
  if (!result.ok) return c.json(result.error, result.status ?? 400)
  return c.json(result.token)
})

oidc.get('/userinfo', async (c) => {
  const bearer = c.req.header('authorization')?.replace('Bearer ', '') ?? ''
  const result = await op.userinfo(bearer)
  if (!result.ok) return c.json({ error: 'invalid_token' }, 401)
  return c.json(result.claims)
})

oidc.post('/introspect', async (c) => {
  const body = await c.req.parseBody()
  const authHeader = c.req.header('authorization') ?? ''
  const result = await op.introspect(String(body.token ?? ''), authHeader)
  return c.json(result)
})

oidc.post('/revoke', async (c) => {
  const body = await c.req.parseBody()
  const authHeader = c.req.header('authorization') ?? ''
  await op.revoke(String(body.token ?? ''), authHeader)
  return c.text('', 200)
})
```

---

## 10. Multi-tenancy

```ts
import { authWithTenant, authResolveTenant } from '@gentleduck/auth/core/tenant'

// Wrap the engine for a specific tenant
const tenantAuth = authWithTenant(auth, 'org-acme')

// Resolve tenant from subdomain / header / JWT
const tenantId = authResolveTenant(request, {
  fromSubdomain: true,
  fromHeader: 'x-tenant-id',
})
```

---

## 11. Compliance Presets

```ts
import { authAssertCompliance, AUTH_SOCI2_PRESET } from '@gentleduck/auth/core/compliance'

// Apply SOC2 password / session overrides and throw on violations
authAssertCompliance(auth.config, AUTH_SOCI2_PRESET)
```

---

## 12. Client (browser)

```ts
import { authCreateClient } from '@gentleduck/auth/client/vanilla'

const client = authCreateClient({ baseUrl: '/auth' })

// Subscribe to session state
const unsub = client.onChange((state) => {
  if (state) console.log('logged in', state.identityId)
  else       console.log('logged out')
})

// Sign in
await client.signIn({ providerId: 'password', input: { email, password } })

// OAuth redirect
await client.beginProvider('google')

// Sign out
await client.signOut()
```

---

## Tips

- **Never** use `AuthMemoryAdapter` in production — it stores nothing across restarts and rejects `strict('production')`.
- **Prefer `AuthArgon2idHasher`** over `AuthScryptHasher` in production. Argon2id won the PHC.
- **Rate-limit key**: the password provider buckets per canonical (trimmed + lowercased) email. Shared across `ALICE@x.com` and `alice@x.com`. Intentional.
- **CSRF**: server adapters (Hono, Express, etc.) run `authCsrfGuard` automatically on POST routes. Make sure your client sends the CSRF token cookie back.
- **OIDC in production**: swap the `AuthMemory*Store` classes for Redis or Drizzle-backed stores — the in-memory ones lose state on restart and don't survive multiple instances.
- **JWT transport** → stateless sessions; no DB hit on `resolveSession`. Trade-off: tokens can't be revoked until they expire. Use short TTLs + refresh tokens.
- **`auth.strict('production')`** is your checklist: limiter, HTTPS baseUrl, no memory adapters, at least one provider, a `lockout` event handler.
