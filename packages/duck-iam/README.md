<p align="center">
  <img src="./public/logo-dark.svg" alt="@gentleduck/iam" width="120"/>
</p>

<h1 align="center">@gentleduck/iam</h1>

<p align="center">
  Modern ABAC/RBAC access control engine. Framework-agnostic core with integrations for Express, NestJS, Hono, Next.js, React, and Vue.
</p>

<p align="center">
  <a href="./LICENSE">MIT</a> -
  <a href="./CHANGELOG.md">Changelog</a> -
  <a href="./SECURITY.md">Security</a> -
  <a href="https://gentleduck.org/duck-iam">Docs</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@gentleduck/iam"><img src="https://img.shields.io/npm/v/@gentleduck/iam.svg" alt="npm"/></a>
  <a href="https://www.npmjs.com/package/@gentleduck/iam"><img src="https://img.shields.io/npm/dm/@gentleduck/iam.svg" alt="downloads"/></a>
  <a href="./LICENSE"><img src="https://img.shields.io/npm/l/@gentleduck/iam.svg" alt="MIT"/></a>
</p>

---

Type-safe authorization engine for TypeScript. RBAC + ABAC with a policy engine, condition evaluation, scoped roles, and integrations for Express, NestJS, Hono, Next.js, React, Vue, and vanilla JS.

Zero runtime dependencies. Tree-shakeable. 23 KB full, under 1 KB per module.

## Install

```bash
npm install @gentleduck/iam
# or
bun add @gentleduck/iam
```

## Quick start

```typescript
import { createIam } from '@gentleduck/iam/core'
import { MemoryAdapter } from '@gentleduck/iam/adapters/memory'

const access = createIam({
  actions: ['create', 'read', 'update', 'delete'] as const,
  resources: ['post', 'comment', 'user'] as const,
  roles: ['viewer', 'editor', 'admin'] as const,
})

const viewer = access.defineRole('viewer').grant('read', 'post').grant('read', 'comment').build()
const editor = access.defineRole('editor').inherits('viewer').grant('update', 'post').build()
const admin = access.defineRole('admin').inherits('editor').grantCRUD('post').grantCRUD('comment').build()

const policy = access
  .policy('blog')
  .rule('owner-edit', (r) => r.allow().on('update').of('post').when((w) => w.isOwner()))
  .build()

const adapter = new MemoryAdapter({
  policies: [policy],
  roles: [viewer, editor, admin],
  assignments: { 'user-1': ['editor'] },
})

const engine = access.createEngine({ adapter })
const allowed = await engine.can('user-1', 'read', { type: 'post', attributes: {} })
// true
```

## Performance

Benchmarked against 6 JS authorization libraries using vitest bench. Simple RBAC check, ops/sec (higher is better):

| Library | ops/sec | vs CASL |
|---------|---------|---------|
| @casl/ability | 16,857,000 | baseline |
| **@gentleduck/iam** [PROD] | 8,233,000 | 2x slower |
| easy-rbac | 5,003,000 | 3.4x slower |
| @rbac/rbac | 2,884,000 | 5.8x slower |
| accesscontrol | 674,000 | 25x slower |
| casbin | 143,000 | 118x slower |

CASL is faster on raw lookups because it pre-compiles rules into a hash table at build time. duck-iam supports dynamic policies that can change at runtime, which costs an extra Map lookup per check.

For the smallest bundle, import only what you use via subpaths:

```typescript
// Engine-only (skip adapters, server middleware, client wrappers)
import { IamEngine, evaluatePolicyFast } from '@gentleduck/iam/core'

// Each adapter, server adapter, and client wrapper is a separate entry
import { MemoryAdapter } from '@gentleduck/iam/adapters/memory'
import { adminRouter } from '@gentleduck/iam/server/express'
import { useAccess } from '@gentleduck/iam/client/react'

// Validator (12 KB) - lazy-loaded by engine.admin.savePolicy on first
// call, or imported directly for standalone validation tooling
import { validatePolicy } from '@gentleduck/iam/core/validate'

// Fluent builder (9 KB) - config-time only, separate subpath
import { policy, defineRole } from '@gentleduck/iam/core/builder'
```

`import * from '@gentleduck/iam'` pulls the everything-barrel (~41 KB
gzipped). Real deployments using subpath imports + tree-shaking come in
at 15-25 KB.

## Features

- **RBAC + ABAC** combined in one engine
- **Policy engine** with 4 intra-policy algorithms (deny-overrides, allow-overrides, first-match, highest-priority) and 3 cross-policy combine modes (and / allow-overrides / first-applicable)
- **18 condition operators** (eq, neq, gt, lt, in, contains, starts_with, matches, exists, subset_of, and more)
- **Scoped roles** for multi-tenant systems
- **Dev/prod mode**: rich Decision objects in development, plain booleans in production
- **Explain API**: full evaluation trace showing exactly why a permission was granted or denied
- **Lifecycle hooks**: `beforeEvaluate`, `afterEvaluate`, `onDeny`, `onError`, `onPolicyError`, `onMetrics`
- **Type-safe config**: actions, resources, roles, and scopes are validated at compile time

### SRE primitives

- **`engine.preload()`** - warm cache at boot
- **`engine.healthCheck()`** - `/healthz`-ready probe with adapter latency + cache hit rate
- **`engine.stats.get()` / `engine.stats.reset()`** - cache hit / miss counters per cache
- **`engine.cache.invalidate()` / `invalidatePolicies()` / `invalidateRoles(id?)` / `invalidateSubject(id)`** - targeted cache flushes
- **`engine.admin.export()` / `import(snapshot, { mode })`** - schema-versioned policy + role snapshots for env promotion
- **`engine.dispose()`** - release the cross-instance invalidator subscription on shutdown
- **`IConfig.adapterTimeoutMs`** - `AbortController`-driven timeout on every adapter read (default 5 s)
- **`IConfig.maxPolicies` / `maxRoles`** - load-time caps that fail closed
- **`IConfig.allowFailOpen`** - explicit opt-in required to combine `mode: 'production'` with `defaultEffect: 'allow'`
- **`IConfig.invalidator`** - cross-instance cache-invalidation broadcaster
- **`createRedisInvalidator`** at `@gentleduck/iam/invalidators/redis` - pub/sub helper with self-echo filter
- **`createMetricsAggregator`** at `@gentleduck/iam/observability/metrics` - p50 / p95 / p99 over `onMetrics` events
- **HttpAdapter retry + per-request timeout + circuit breaker** (retries, backoff, threshold, cooldown)
- **Required `authorize` callback** on every admin router (Express, Hono, Next, Nest)

## Integrations

### Server middleware

```typescript
// Express
import { guard, adminRouter } from '@gentleduck/iam/server/express'
app.delete('/posts/:id', guard(engine, 'delete', 'post'), handler)
app.use('/admin', adminRouter(engine, { authorize: (req) => isAdmin(req) })(() => express.Router()))

// Hono
import { guard, bindAdminRouter } from '@gentleduck/iam/server/hono'
app.delete('/posts/:id', guard(engine, 'delete', 'post'), handler)
bindAdminRouter(adminApp, engine, { authorize: (c) => isAdmin(c) })

// NestJS
import { nestAccessGuard, Authorize, createAdminOperations } from '@gentleduck/iam/server/nest'
@Authorize({ action: 'delete', resource: 'post' })

// Next.js
import { withAccess, createAdminHandlers } from '@gentleduck/iam/server/next'
export const DELETE = withAccess(engine, 'delete', 'post', handler)
```

### Client libraries

```typescript
// React
import { createAccessControl } from '@gentleduck/iam/client/react'
const { AccessProvider, useAccess, Can, Cannot } = createAccessControl(React)

// Vue
import { createVueAccess } from '@gentleduck/iam/client/vue'
const { useAccess, Can, Cannot } = createVueAccess(vue)

// Vanilla JS
import { AccessClient } from '@gentleduck/iam/client/vanilla'
const client = await AccessClient.fromServer('/api/permissions')
client.can('read', 'post') // boolean
```

### Database adapters

```typescript
import { MemoryAdapter } from '@gentleduck/iam/adapters/memory'
import { FileAdapter } from '@gentleduck/iam/adapters/file'
import { PrismaAdapter } from '@gentleduck/iam/adapters/prisma'
import { DrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { RedisAdapter } from '@gentleduck/iam/adapters/redis'
import { HttpAdapter } from '@gentleduck/iam/adapters/http'
```

### Operability

```typescript
import { createRedisInvalidator } from '@gentleduck/iam/invalidators/redis'
import { createMetricsAggregator } from '@gentleduck/iam/observability/metrics'

const metrics = createMetricsAggregator()
const engine = new IamEngine({
  adapter,
  invalidator: createRedisInvalidator({ client: redis }),
  hooks: { onMetrics: metrics.record },
})

await engine.preload()
app.get('/healthz', async (_, res) => res.json(await engine.healthCheck()))
app.get('/metrics', (_, res) => res.json(metrics.snapshot()))
```

See the [production deployment guide](https://gentleduck.org/duck-iam/duck-iam/guides/production) for cache TTL trade-offs, multi-node invalidation patterns, fail-closed defaults, and SLO targets.

## Module sizes (gzipped)

| Module | Size |
|--------|------|
| Core engine (typical import) | ~15 KB |
| `core/validate` (admin only, lazy-loaded) | 12 KB |
| `core/builder` (config-time only) | 9 KB |
| `core/explain` (dev-mode trace) | separate chunk |
| Each adapter | 1.7 - 6 KB |
| Each server middleware | 2.4 - 3.7 KB |
| Each client library | 1.2 - 2.0 KB |

The "full" bundle headline in benchmarks (~41 KB) is the worst-case
"import everything" number - what `import * from '@gentleduck/iam'`
would pull. Realistic deployments end up at 15-25 KB because adapters,
server middleware, and clients live behind subpath imports and the
validator is lazy-loaded only when admin write paths run. See the
[benchmarks page](https://gentleduck.org/duck-iam/duck-iam/benchmarks)
for per-profile measurements.

## Docs

- Site: [gentleduck.org/duck-iam](https://gentleduck.org/duck-iam)
- Devtools: import `@gentleduck/iam/dt` to inspect policy evaluation inside your app
- Sibling repos: [`@gentleduck/auth`](https://www.npmjs.com/package/@gentleduck/auth), [`@gentleduck/ui`](https://github.com/gentleeduck/duck-ui), [`@gentleduck/upload`](https://github.com/gentleeduck/duck-upload), [`@gentleduck/md`](https://github.com/gentleeduck/duck-md)

## Contributing

PR checklist + style notes in the repo's [`CONTRIBUTING.md`](https://github.com/gentleeduck/duck-iam/blob/main/CONTRIBUTING.md).
Security disclosures: [`SECURITY.md`](./SECURITY.md).

## License

MIT. See [`LICENSE`](./LICENSE).
