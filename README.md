<p align="center">
  <img src="./public/logo-dark.svg" alt="GentleDuck auth + iam" width="120"/>
</p>

<h1 align="center">GentleDuck auth + iam</h1>

<p align="center">
  TypeScript-first authentication and authorization for modern apps. Framework-agnostic. Batteries included. No hosted plane.
</p>

<p align="center">
  <a href="./LICENSE">MIT</a> -
  <a href="https://gentleduck.org">Docs</a> -
  <a href="./CONTRIBUTING.md">Contributing</a> -
  <a href="./SECURITY.md">Security</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@gentleduck/auth"><img src="https://img.shields.io/npm/v/@gentleduck/auth.svg?label=%40gentleduck%2Fauth" alt="@gentleduck/auth on npm"/></a>
  <a href="https://www.npmjs.com/package/@gentleduck/iam"><img src="https://img.shields.io/npm/v/@gentleduck/iam.svg?label=%40gentleduck%2Fiam" alt="@gentleduck/iam on npm"/></a>
  <a href="./LICENSE"><img src="https://img.shields.io/npm/l/@gentleduck/iam.svg" alt="MIT"/></a>
</p>

---

This monorepo ships two complementary packages that you can use independently or together.

## Packages

| Package | npm | What |
|---|---|---|
| [`@gentleduck/auth`](packages/duck-auth) | [![npm](https://img.shields.io/npm/v/@gentleduck/auth.svg)](https://www.npmjs.com/package/@gentleduck/auth) | **AuthN** - faceted authentication: passwords, magic-link, passkeys, OAuth (google / github / microsoft / discord / linkedin / apple / generic OIDC), SAML, api-keys, MFA (TOTP / WebAuthn / backup-codes), DPoP, JWT + refresh, webhooks, M2M, compliance presets, OpenAPI spec generator |
| [`@gentleduck/iam`](packages/duck-iam) | [![npm](https://img.shields.io/npm/v/@gentleduck/iam.svg)](https://www.npmjs.com/package/@gentleduck/iam) | **AuthZ** - RBAC + ABAC + ReBAC policy engine with explain trace, scoped roles, devtools, 18 condition operators, multi-tenant scope, lifecycle hooks |

The two packages are independent: use `@gentleduck/auth` alone for sign-in flows, use `@gentleduck/iam` alone as a standalone policy engine, or wire them together (sessions from `@gentleduck/auth` resolve to subject IDs that `@gentleduck/iam` authorizes).

## Install

```sh
# Authentication only
bun add @gentleduck/auth

# Authorization only
bun add @gentleduck/iam

# Both
bun add @gentleduck/auth @gentleduck/iam
```

## Quick start

### Authentication (`@gentleduck/auth`)

```ts
import { AuthRoot, InMemoryEvents, ScryptHasher } from '@gentleduck/auth/core'
import { CookieTransport } from '@gentleduck/auth/core/transport'
import { MemoryAuthAdapter } from '@gentleduck/auth/adapters/memory'
import { MemoryLimiter } from '@gentleduck/auth/limiters/memory'
import { password } from '@gentleduck/auth/providers/password'

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

auth.providers.register(password({
  findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
  passwords: auth.passwords,
}))
```

### Authorization (`@gentleduck/iam`)

```ts
import { createAccessConfig } from '@gentleduck/iam/core'
import { MemoryAdapter } from '@gentleduck/iam/adapters/memory'

const access = createAccessConfig({
  actions: ['create', 'read', 'update', 'delete'] as const,
  resources: ['post', 'comment'] as const,
  roles: ['viewer', 'editor', 'admin'] as const,
})

const editor = access
  .defineRole('editor')
  .grant('read', 'post').grant('update', 'post')
  .build()

const adapter = new MemoryAdapter({ roles: [editor], assignments: { 'user-1': ['editor'] } })
const engine = access.createEngine({ adapter })

await engine.can('user-1', 'update', { type: 'post', attributes: {} })
// true
```

### Both together

`@gentleduck/auth` resolves the session and gives you a `session.identityId`. Feed that into `@gentleduck/iam`'s `engine.can(subjectId, action, resource)` to authorize the request. The two packages have no inter-dependency at the type level: they compose at the application layer.

## Workspace

| Path | Package | Role |
|---|---|---|
| [`packages/duck-auth`](packages/duck-auth) | [`@gentleduck/auth`](https://www.npmjs.com/package/@gentleduck/auth) | Authentication engine + providers / transports / adapters / channels / clients |
| [`packages/duck-iam`](packages/duck-iam) | [`@gentleduck/iam`](https://www.npmjs.com/package/@gentleduck/iam) | Authorization engine + RBAC / ABAC / ReBAC + devtools (`@gentleduck/iam/dt`) |

### Subpath exports

Both packages publish a wide subpath export tree so you import only what you wire.

**`@gentleduck/auth`** (~50 subpaths):

| Subpath | What |
|---|---|
| `/core`, `/core/transport`, `/core/transport/dpop` | `AuthRoot` + transports |
| `/providers/{password,magic-link,passkey,api-key,saml}` | Auth providers |
| `/providers/oauth/{google,github,microsoft,discord,linkedin,apple,core}` | OAuth providers |
| `/adapters/memory`, `/adapters/redis`, `/adapters/sql`, `/adapters/drizzle/{pg,mysql,sqlite}`, `/adapters/prisma` | Storage adapters |
| `/server/{express,hono,next,fastify,koa,nestjs,elysia,grpc,generic}` | Framework adapters |
| `/client/{react,vue,solid,svelte,vanilla}` | Client libraries |
| `/channels/{console,smtp,resend,twilio,webpush,ses,noop,test}` | Channel adapters |
| `/captcha/{turnstile,hcaptcha,recaptcha}` | Captcha verifiers |
| `/cli`, `/openapi`, `/oidc`, `/limiters/memory`, `/i18n`, `/telemetry` | Tooling |

**`@gentleduck/iam`** (~20 subpaths):

| Subpath | What |
|---|---|
| `/core`, `/core/validate`, `/core/builder`, `/core/explain` | Engine + admin write validator + fluent builder + explain trace |
| `/server/{next,express,nest,hono,generic}` | Framework adapters |
| `/client/{react,vue,vanilla}` | Client libraries |
| `/adapters/{memory,file,prisma,drizzle,redis,http}` | Storage adapters |
| `/invalidators/redis`, `/observability/metrics` | Operability |
| `/dt` | Devtools UI panel |

## Examples

| Path | Stack |
| --- | --- |
| [`apps/duck-auth-demo`](apps/duck-auth-demo) | End-to-end `@gentleduck/auth` reference: password + magic-link + OAuth + passkey + MFA, Postgres via drizzle, Hono server, Storybook UI |
| [`examples/blogduck`](examples/blogduck) | Next.js + Prisma blog with editor / reader roles (`@gentleduck/iam`) |
| [`examples/docduck`](examples/docduck) | Next.js + Hocuspocus collaborative docs |
| [`examples/tanstack-start`](examples/tanstack-start) | TanStack Start app with posthog + iam |
| [`examples/vite`](examples/vite) | Vite + React minimal demo |

## Build

```sh
bun install
bunx turbo run build      --filter='./packages/*'
bunx turbo run test       --filter='./packages/*'
bunx turbo run check-types --filter='./packages/*'
```

## Docs

- Authentication: [gentleduck.org/duck-auth](https://gentleduck.org/duck-auth)
- Authorization: [gentleduck.org/duck-iam](https://gentleduck.org/duck-iam)
- Devtools: import `@gentleduck/iam/dt` to inspect policy evaluation inside your app
- Sibling repos: [`@gentleduck/ui`](https://github.com/gentleeduck/duck-ui), [`@gentleduck/upload`](https://github.com/gentleeduck/duck-upload), [`@gentleduck/md`](https://github.com/gentleeduck/duck-md)

## Contributing

PR checklist + style notes in [`CONTRIBUTING.md`](CONTRIBUTING.md).
Security disclosures: [`SECURITY.md`](SECURITY.md).
Behaviour: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

MIT. See [`LICENSE`](LICENSE).
