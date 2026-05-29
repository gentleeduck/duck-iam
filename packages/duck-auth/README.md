# @gentleduck/auth

Authentication for modern TypeScript apps. Faceted, framework-agnostic,
transport-pluggable. Pairs with
[`@gentleduck/iam`](../duck-iam) for authorization.

## Why

Every TypeScript auth library makes you choose one of:

- **Framework lock-in** (NextAuth, Auth.js)
- **Hosted control plane** (Clerk, WorkOS, Stytch)
- **DIY on Lucia + passport + your own glue**

`@gentleduck/auth` is the third option, but unified: framework-agnostic
core, batteries-included adapters, no hosted plane. You wire it into
Express, Hono, Next.js, vanilla Web Fetch, or your own router with one
adapter import.

## Install

```sh
bun add @gentleduck/auth          # or npm / pnpm / yarn
```

Optional peer dependencies (install only what you wire):

| Peer | When you need it |
|---|---|
| `@node-rs/argon2` | Argon2id password hashing (FIPS / HIPAA presets) |
| `@simplewebauthn/server` | Passkey provider |
| `ioredis` or `@upstash/redis` | Redis-backed session / idempotency / limiter / events / DPoP nonce stores |
| `nodemailer` (or compatible) | SMTP channel |

## 60-second quickstart

```ts
import { AuthRoot, InMemoryEvents, ScryptHasher } from '@gentleduck/auth/core'
import { CookieTransport } from '@gentleduck/auth/core/transport'
import { MemoryAuthAdapter } from '@gentleduck/auth/adapters/memory'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'

const adapter = new MemoryAuthAdapter()

export const auth = new AuthRoot({
  baseUrl: 'http://localhost:3000',
  transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
  stores: {
    identities: adapter.identities,
    sessions: adapter.sessions,
    credentials: adapter.credentials,
  },
  events: new InMemoryEvents(),
  limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
  passwords: { hasher: new ScryptHasher() },
})
```

Then mount the framework adapter (`server/express`, `server/hono`,
`server/next`, `server/generic`) and you're done.

## Or scaffold it via the CLI

```sh
bunx @gentleduck/auth init src/auth                # quickstart
bunx @gentleduck/auth init src/auth --production   # Redis + JWT + Argon2id
bunx @gentleduck/auth doctor                       # run AuthRoot.strict()
bunx @gentleduck/auth keys generate hs256          # mint a JWT signing secret
bunx @gentleduck/auth keys generate ec256          # mint an ES256 keypair (DPoP)
```

## What's in the box

### Core (`@gentleduck/auth/core`)

- `AuthRoot` - 14-facet root: identities, sessions, credentials,
  passwords, mfa, recovery, flows, csrf, idempotency, audit, admin,
  events, api-keys, telemetry
- `AuthErrorObject` + typed error codes (`AUTH/UNAUTHENTICATED`,
  `AUTH/MFA_REQUIRED`, `AUTH/RATE_LIMITED`, ...) with wire-safe JSON
- `ScryptHasher` (built-in) + `Argon2idHasher` (lazy peerDep)
- `InMemoryEvents`

### Transports (`@gentleduck/auth/core/transport`)

- `CookieTransport` - `__Host-` prefix + HttpOnly + SameSite=Lax
- `BearerTransport` - opaque tokens
- `JwtTransport` - HS256 JWT + opaque refresh cookie + JWKS hook
- `CompositeTransport` - combine multiple
- `DPoPVerifier` + `MemoryDPoPNonceStore` + `computeJwkThumbprint`
  + `bindPayloadToDPoP` (RFC 9449)

### Providers

| Path | What |
|---|---|
| `@gentleduck/auth/providers/password` | Email + password |
| `@gentleduck/auth/providers/magic-link` | Passwordless one-time link |
| `@gentleduck/auth/providers/oauth/google` | Google OAuth (PKCE + nonce) |
| `@gentleduck/auth/providers/oauth/github` | GitHub OAuth (PKCE + state) |
| `@gentleduck/auth/providers/passkey` | WebAuthn passkey (lazy peerDep on `@simplewebauthn/server`) |
| `@gentleduck/auth/providers/api-key` | Long-lived bearer keys via `ApiKeysFacet` |

### Adapters

| Path | What |
|---|---|
| `@gentleduck/auth/adapters/memory` | Identity + credential + session + org (dev/test) |
| `@gentleduck/auth/adapters/redis` | Session + idempotency + limiter + events + DPoP nonce stores (production) |
| `@gentleduck/auth/limiters/memory` | Token-bucket limiter (dev/test) |

### Channels

| Path | What |
|---|---|
| `@gentleduck/auth/channels/console` | Console / Noop / Test channels (dev + test) |
| `@gentleduck/auth/channels/smtp` | Nodemailer-compatible SMTP relay |

### Servers

| Path | What |
|---|---|
| `@gentleduck/auth/server/express` | Express middleware |
| `@gentleduck/auth/server/hono` | Hono middleware |
| `@gentleduck/auth/server/next` | Next.js route handlers |
| `@gentleduck/auth/server/generic` | Web Fetch executor (anything else) |

### Clients

| Path | What |
|---|---|
| `@gentleduck/auth/client/vanilla` | Promise-based `signIn` / `signOut` / `useSession` |
| `@gentleduck/auth/client/react` | `<AuthProvider>` + `useSession` + `useSignIn` hooks |

### Tooling

| Path | What |
|---|---|
| `@gentleduck/auth/cli` | `duck-auth init` / `doctor` / `keys generate` |
| `@gentleduck/auth/openapi` | `buildOpenApiSpec` + `renderOpenApiYaml` |

## Security posture

`AuthRoot.strict()` runs every production-grade gate before boot:

- Cookie transport must be `secure: true`
- A non-memory `Limiter` must be wired
- A non-memory `Session.IStore` must be wired
- Listeners must be attached to the `lockout` event
- Compliance preset matches the regulatory scope
- DPoP verifier wired when bearer tokens are issued

See [`THREAT-MODEL.md`](./THREAT-MODEL.md) for the STRIDE / OWASP ASVS
mapping of every threat the library mitigates and every threat the
host app must own.

## Status

Pre-1.0. Per-component status is tracked in [`DESIGN.md`](./DESIGN.md).

| Surface | Status |
|---|---|
| Core (14 facets) | shipped |
| Transports (cookie, bearer, jwt, composite, DPoP) | shipped |
| Adapters (memory, redis) | shipped |
| Providers (password, magic-link, oauth, passkey, api-key) | shipped |
| Channels (console, smtp) | shipped |
| CLI (init / doctor / keys) | shipped |
| OpenAPI generator | shipped |
| Drizzle / Prisma SQL adapters | planned v1.2 |
| OpenTelemetry | planned v1.2 |
| Channels: Resend / Twilio / web-push | planned v1.2 |

## License

MIT - GentleDuck
