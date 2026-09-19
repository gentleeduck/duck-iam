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

One runtime dependency (`uuid`, pulled in only by the Drizzle schema helpers). Tree-shakeable - see [Module sizes](#module-sizes-gzipped) below for real per-module numbers.

## Install

```bash
npm install @gentleduck/iam
# or
bun add @gentleduck/iam
```

## Quick start

```typescript
import { createIam } from '@gentleduck/iam/core'
import { IamMemoryAdapter } from '@gentleduck/iam/adapters/memory'

const access = createIam({
  actions: ['create', 'read', 'update', 'delete'] as const,
  resources: ['post', 'comment', 'user'] as const,
  roles: ['viewer', 'editor', 'admin'] as const,
})

const viewer = access.defineRole('viewer').grant('read', 'post').grant('read', 'comment').build()
const editor = access.defineRole('editor').inherits('viewer').grant('update', 'post').build()
const admin = access.defineRole('admin').inherits('editor').grantCRUD('post').grantCRUD('comment').build()

const policy = access
  .definePolicy('blog')
  .rule('owner-edit', (r) => r.allow().on('update').of('post').when((w) => w.isOwner()))
  .build()

const adapter = new IamMemoryAdapter({
  policies: [policy],
  roles: [viewer, editor, admin],
  assignments: { 'user-1': ['editor'] },
})

const engine = access.createEngine({ adapter })
const allowed = await engine.can('user-1', 'read', { type: 'post', attributes: {} })
// true
```

## Performance

Benchmarked against 5 other JS authorization libraries using vitest bench
(`bun run bench`). Every number in this section was measured at **5.6.0** on one
machine in a single run and has not been re-measured since; read them as ratios
from that run, not as a current reading of your hardware. Re-run `bun run bench`
before quoting any of them. Two different things get measured - keep them
separate.

**Rule-matching only** (no adapter, no engine wrapper), ops/sec:

| Library | ops/sec | vs CASL |
|---------|---------|---------|
| @casl/ability | ~17.0M | baseline |
| easy-rbac | ~5.0M | 3.4x slower |
| @rbac/rbac | ~3.3M | 5.2x slower |
| **@gentleduck/iam** `iamEvaluateFast()` | ~7.6M | 2.2x slower |
| accesscontrol | ~1.3M | 12.8x slower |
| casbin | ~208K | 82x slower |

**`engine.can()`** - the real entry point, full stack (adapter + hooks +
subject resolution + the compiled table):

| Mode | ops/sec | vs CASL |
|------|---------|---------|
| `mode: 'production'` (compiled table) | ~1.15M | ~14x slower |
| @casl/ability (ability pre-built, `.can()`) | ~17.0M | baseline |

`mode: 'development'` runs the same compiled table for the verdict and *also*
runs the interpreter, to recover the `reason`/`policy`/`rule` provenance the
table erases at compile time and to assert the two agree. That costs roughly
2.4x production on the same machine. That is the intent: development is where a
table/interpreter disagreement should surface, and production is where the
second evaluator would be pure overhead.

CASL is a narrower tool: one flat rule set, fully sync, no persistence
layer. `engine.can()` also runs a policy engine (4 combining algorithms
across N named policies), RBAC role inheritance, an adapter/cache/
invalidation layer, and lifecycle hooks - and it's `async`. That gap is
the cost of that surface, not inefficiency to chase down.

In practice it isn't the bottleneck: ~1.15M ops/sec is ~0.87µs per check
on one core - network, DB, and serialization around it cost more than
the check itself in any real request. Throughput doesn't degrade with
catalog size either; the compiled table is an O(1) index lookup
regardless of how many roles or policies exist. What actually
constrains scale is catalog *shape* - role count, very wide
action x resource grids, and deeply nested hierarchical resource types -
not raw request throughput. Past 32 roles the 32-bit grant mask can no
longer address them all, so the engine warns once and falls back to the
interpreter: still correct, no longer O(1).

For the smallest bundle, import only what you use via subpaths:

```typescript
// Engine-only (skip adapters, server middleware, client wrappers)
import { IamEngine, iamEvaluatePolicyFast } from '@gentleduck/iam/core'

// Each adapter, server adapter, and client wrapper is a separate entry
import { IamMemoryAdapter } from '@gentleduck/iam/adapters/memory'
import { iamAdminRouter } from '@gentleduck/iam/server/express'
import { createIamAccessControl } from '@gentleduck/iam/client/react'

// Validator (12 KB) - lazy-loaded by engine.admin.savePolicy on first
// call, or imported directly for standalone validation tooling
import { validatePolicy } from '@gentleduck/iam/core/validate'

// Fluent builder (9 KB) - config-time only, separate subpath
import { definePolicy, defineRole } from '@gentleduck/iam/core/builder'
```

`import * from '@gentleduck/iam'` pulls the everything-barrel (~41 KB
gzipped). Real deployments using subpath imports + tree-shaking come in
at 15-25 KB.

## Features

- **RBAC + ABAC** combined in one engine
- **Policy engine** with 4 intra-policy algorithms (deny-overrides, allow-overrides, first-match, highest-priority) and 3 cross-policy combine modes (and / allow-overrides / first-applicable)
- **19 condition operators** (eq, neq, gt, lt, in, contains, starts_with, matches, exists, subset_of, before, after, and more)
- **Scoped roles** for multi-tenant systems
- **Dev/prod mode**: `check()` returns an `IDecision` in development and a bare boolean in production; `can()` returns a boolean in both
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
- **`IConfig.adapterTimeoutMs`** - `AbortController`-driven timeout on every adapter call, decision path and `engine.admin` alike (default 5 s)
- **`IConfig.hookTimeoutMs`** - bound on a promise a hook returns (default 5 s; `0` waits indefinitely)
- **`IConfig.maxPolicies` / `maxRoles`** - load-time caps that fail closed
- **`IConfig.allowFailOpen`** - explicit opt-in required whenever `defaultEffect` is `'allow'`, in every mode
- **`IConfig.invalidator`** - cross-instance cache-invalidation broadcaster
- **`createIamRedisInvalidator`** at `@gentleduck/iam/invalidators/redis` - pub/sub helper with self-echo filter
- **`iamCreateMetricsAggregator`** at `@gentleduck/iam/observability/metrics` - p50 / p95 / p99 over `onMetrics` events
- **HttpAdapter retry + per-request timeout + circuit breaker** (retries, backoff, threshold, cooldown)
- **Required `authorize` callback** on every admin router (Express, Hono, Next, Nest)

## Integrations

### Server middleware

```typescript
// Express
import { iamGuard, iamAdminRouter } from '@gentleduck/iam/server/express'
app.delete('/posts/:id', iamGuard(engine, 'delete', 'post'), handler)
app.use('/admin', iamAdminRouter(engine, { authorize: (req) => isAdmin(req) })(() => express.Router()))

// Hono
import { iamGuard, iamBindAdminRouter } from '@gentleduck/iam/server/hono'
app.delete('/posts/:id', iamGuard(engine, 'delete', 'post'), handler)
iamBindAdminRouter(adminApp, engine, { authorize: (c) => isAdmin(c) })

// NestJS
import { iamNestAccessGuard, IamAuthorize, createIamAdminOperations } from '@gentleduck/iam/server/nest'
@IamAuthorize({ action: 'delete', resource: 'post' })

// Next.js
import { withIamAccess, createIamAdminHandlers } from '@gentleduck/iam/server/next'
export const DELETE = withIamAccess(engine, 'delete', 'post', handler, {
  getUserId: async () => (await auth()).userId, // required - headers are spoofable
})
```

### Client libraries

```typescript
// React
import { createIamAccessControl } from '@gentleduck/iam/client/react'
const { AccessProvider, useAccess, Can, Cannot } = createIamAccessControl(React)

// Vue
import { createIamVueAccess } from '@gentleduck/iam/client/vue'
const { useAccess, Can, Cannot } = createIamVueAccess(vue)

// Vanilla JS
import { IamAccessClient } from '@gentleduck/iam/client/vanilla'
const client = await IamAccessClient.fromServer('/api/permissions')
client.can('read', 'post') // boolean
```

### Database adapters

```typescript
import { IamMemoryAdapter } from '@gentleduck/iam/adapters/memory'
import { IamFileAdapter } from '@gentleduck/iam/adapters/file'
import { IamPrismaAdapter } from '@gentleduck/iam/adapters/prisma'
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { IamRedisAdapter } from '@gentleduck/iam/adapters/redis'
import { IamHttpAdapter } from '@gentleduck/iam/adapters/http'
```

### Transactions

Writes and reads can run on a transaction you own. `withTransaction(tx)` returns a view of
the engine bound to your transaction handle; the handle is opaque to duck-iam and is handed
straight back to your adapter.

```typescript
let pending
await db.transaction(async (tx) => {
  const perms = engine.withTransaction(tx)
  await perms.admin.assignRole(userId, 'admin', orgId)
  await tx.insert(members).values({ userId, orgId })
  pending = perms.pending
})
await pending.flush()   // invalidate and broadcast only after the commit
```

Writes go through `.admin`, the same interface as `engine.admin`, so there is one write
surface rather than two.

Reads on the bound view run against transaction-local caches, so they see the transaction's
own uncommitted grants; the shared engine keeps answering from its warm caches, which the
transaction never pollutes. An empty local cache always misses through to the bound adapter,
which is what makes a read-after-write inside the transaction correct.

**Cache invalidations do not fire inside a transaction** - including the `config.invalidator`
fleet broadcast. They buffer in `pending`, de-duplicated, and fire on `flush()`. A
rolled-back grant therefore never evicts another node's cache for a write that did not
happen. `pending.discard()` drops the buffer for an explicit rollback path.

`withTransaction` needs an adapter that implements `withClient`. The drizzle and prisma
adapters do; memory, file, redis and http do not - they have no transaction to join - and
`withTransaction` throws rather than silently leaving writes outside yours.

### Batch writes

`assignRoles`, `revokeRoles` and `moveRoleScopes` take a list and report per-row outcomes.
(`invalidateSubjects` also takes a list, but it is a cache drop rather than a write and
returns `void`.)

```typescript
const result = await engine.admin.assignRoles([
  { subjectId: 'u1', roleId: 'admin' },
  { subjectId: 'u2', roleId: 'editor', scope: 'org-1' },
])
result.applied   // 2
result.outcomes  // one entry per input row, in input order
```

Every row is validated before any is written, so a malformed row aborts the batch instead
of half-applying it. Each affected subject is invalidated once, however many rows named it.
The drizzle adapter collapses the writes into one `INSERT` and one `DELETE` - the `DELETE`
needs `or` in the adapter's `ops`, and revokes row by row without it. Adapters with no
set-based form loop, so every adapter supports every batch form.

Each outcome carries the row it answers, so nothing has to parse an id back into a triple,
and two structurally identical rows stay separate entries:

```typescript
const result = await engine.admin.assignRoles(rows)
result.outcomes.map((o) => o.row) // the rows you passed in, same objects, same order
```

Both role writes are idempotent, so every row is `ok`: granting a role a subject already
holds is success, not a miss, exactly as the single-row `assignRole` treats it. `changed`
carries the finer answer:

```typescript
const again = await engine.admin.assignRoles([{ subjectId: 'u1', roleId: 'admin' }])
again.applied // 1 - the grant is in place

// `ok` is always `true`: a malformed row aborts the whole batch before any write, so
// there is no failed-row arm to narrow on. Read `value` directly.
const [outcome] = again.outcomes
outcome?.value.changed // false - this call is not what put it there
```

| `changed` | Meaning |
|---|---|
| `true` | this row accounts for a write the statement made |
| `false` | the row was already in the requested state, or an earlier row of the batch already accounts for that write |
| absent | the adapter could not say, and did not guess |

It is absent on MySQL, which has no `RETURNING`, and on every adapter that loops the
single-row methods, which return `void`. Neither pays for an extra read to find out.

Every write is credited to exactly one row - the first that accounts for it. Listing the
same triple twice reports `true` then `false` rather than both rows claiming a write the
database made once, and revoking `{u1, admin}` alongside `{u1, admin, scope: 'org-1'}` credits
the wildcard row, which already covers the narrower one. Neither is rejected; both are
answered honestly.

### Operability

```typescript
import { createIamRedisInvalidator } from '@gentleduck/iam/invalidators/redis'
import { iamCreateMetricsAggregator } from '@gentleduck/iam/observability/metrics'

const metrics = iamCreateMetricsAggregator()
const engine = new IamEngine({
  adapter,
  invalidator: createIamRedisInvalidator({ client: redis }),
  hooks: { onMetrics: metrics.record },
})

await engine.preload()
app.get('/healthz', async (_, res) => res.json(await engine.healthCheck()))
app.get('/metrics', (_, res) => res.json(metrics.snapshot()))
```

The invalidator's `client` needs two Redis connections, not one - a subscribed
connection cannot issue other commands - and takes a `secret` for HMAC-SHA256
envelope signing, which should be set in production.

See the [production deployment guide](https://gentleduck.org/duck-iam/duck-iam/guides/production) for cache TTL trade-offs, multi-node invalidation patterns, fail-closed defaults, and SLO targets.

## Module sizes (gzipped)

Measured at 5.6.0, same run as the performance figures above.

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

- **Reference (start here): [`docs/reference/`](./docs/reference/README.md)** - eleven pages
  covering the package subsystem by subsystem, written against the source. The engine and its
  config, the operator table, roles and scope, validation, the builder and traces, every
  adapter, the four server integrations, the clients, the devtools, and operations.
- Site: [gentleduck.org/duck-iam](https://gentleduck.org/duck-iam)
- Compiled engine internals (wildcard buckets, role bitmasks, the compiled table, with diagrams): [`docs/compiled-engine-explained.md`](./docs/compiled-engine-explained.md)
- Engine rewrite design history + known limits: [`docs/engine-rewrite.md`](./docs/engine-rewrite.md)
- Devtools: import `@gentleduck/iam/dt` to inspect policy evaluation inside your app
- Sibling repos: [`@gentleduck/auth`](https://www.npmjs.com/package/@gentleduck/auth), [`@gentleduck/ui`](https://github.com/gentleeduck/duck-ui), [`@gentleduck/upload`](https://github.com/gentleeduck/duck-upload), [`@gentleduck/md`](https://github.com/gentleeduck/duck-md)

## Contributing

PR checklist + style notes in the repo's [`CONTRIBUTING.md`](https://github.com/gentleeduck/duck-iam/blob/main/CONTRIBUTING.md).
Security disclosures: [`SECURITY.md`](./SECURITY.md).

## License

MIT. See [`LICENSE`](./LICENSE).
