# duck-iam Setup Guide

Full setup for `@gentleduck/iam` — RBAC + ABAC policy engine with typed builders.

---

## Install

```bash
bun add @gentleduck/iam
# optional peer deps
bun add drizzle-orm           # drizzle adapter
bun add ioredis               # redis adapter / invalidator
```

---

## 1. Core Concepts

duck-iam is a **two-layer** engine:

| Layer | What it does |
|---|---|
| `createIam(schema)` | Locks down your action / resource / role / scope vocabulary at compile-time |
| `IamEngine` | Evaluates `can(subject, action, resource)` at runtime against policies + roles |

You define the schema once. Every builder method, `can()`, `check()`, and `permissions()` call is then constrained to those exact strings — typos are compile errors.

---

## 2. Define the Schema

```ts
// src/iam.ts
import { createIam } from '@gentleduck/iam'

// The shape the typed dot-paths are derived from. The key names matter:
// `subject`, `environment` and `resourceAttributes` are what `.attr()`,
// `.env()` and `.resourceAttr()` read. `resourceAttributes` is keyed by
// resource type, which is what makes `.resourceAttr()` narrow per resource.
interface AppContext {
  subject: { id: string; roles: string[]; attributes: { orgId: string; tier: 'free' | 'pro' } }
  resourceAttributes: {
    post: { ownerId: string; status: 'draft' | 'ready' | 'published' }
    comment: { ownerId: string }
  }
  environment: { region: string; hour: number }
}

export const iam = createIam({
  actions:   ['create', 'read', 'update', 'delete', 'publish', 'archive'] as const,
  resources: ['post', 'comment', 'user', 'org', 'invoice'] as const,
  roles:     ['viewer', 'editor', 'admin', 'billing'] as const,
  scopes:    ['org:acme', 'org:beta'] as const,
  context:   {} as unknown as AppContext,
})
```

`iam` now exposes typed builders:

```ts
iam.defineRole('viewer')          // TRole constrained
iam.definePolicy('my-policy')     // typed RuleBuilder
iam.defineRule('my-rule')
iam.when()
iam.createEngine(config)
iam.checks([...])                 // typed permission checks
iam.validateRoles(roles)
iam.validatePolicy(input)
```

---

## 3. Define Roles

Roles are RBAC grants: subject `X` with role `R` gets `action` on `resource`.

```ts
// src/roles.ts
import { iam } from './iam'

export const viewerRole = iam.defineRole('viewer')
  .grant('read', 'post')
  .grant('read', 'comment')
  .build()

export const editorRole = iam.defineRole('editor')
  .inherits('viewer')             // inherits all viewer grants
  .grant('create', 'post')
  .grant('update', 'post')
  .grant('create', 'comment')
  .grant('update', 'comment')
  .build()

export const adminRole = iam.defineRole('admin')
  .inherits('editor')
  .grant('delete', 'post')
  .grant('delete', 'comment')
  .grant('delete', 'user')
  .grant('create', 'user')
  .build()

export const billingRole = iam.defineRole('billing')
  .grant('read',   'invoice')
  .grant('create', 'invoice')
  .build()

export const roles = [viewerRole, editorRole, adminRole, billingRole]
```

---

## 4. Define Policies (ABAC)

Policies hold rules. A rule states an effect (`allow` / `deny`), the actions and
resources it covers, an optional scope, and the conditions under which it fires.
Conditions are built with `when(w => ...)`; chained calls are ANDed, and `.or()`
/ `.and()` / `.not()` nest a group.

```ts
// src/policies.ts
import { iam } from './iam'

// Only the owner OR an admin can update a post
export const postOwnerPolicy = iam.definePolicy('post-owner')
  .name('Post owner or admin may update')
  .algorithm('deny-overrides')
  .rule('owner-or-admin', r => r
    .allow()
    .on('update')
    .of('post')
    .when(w => w.or(o => o.isOwner().role('admin'))),
  )
  .build()

// Only allow publish on posts that are in 'ready' state
export const publishGatePolicy = iam.definePolicy('publish-gate')
  .name('Publish only what is ready')
  .rule('ready-editors-only', r => r
    .allow()
    .on('publish')
    .of('post')
    .when(w => w.resourceAttr('status', 'eq', 'ready').role('editor')),
  )
  .build()

// Multi-tenant: editors act only inside their own org
export const orgScopePolicy = iam.definePolicy('org-scope')
  .name('Editors act only inside their own org')
  .rule('own-org-only', r => r
    .allow()
    .on('create', 'update')
    .of('post')
    .forScope('org:acme')
    .when(w => w.role('editor').attr('orgId', 'eq', 'acme')),
  )
  .build()

export const policies = [postOwnerPolicy, publishGatePolicy, orgScopePolicy]
```

These three are pinned by `guide-abac-examples.test.ts` in the package, so what
you read here is what the builders actually accept.

### Policy builder

| Method | What it does |
|---|---|
| `.name(s)` / `.desc(s)` / `.version(n)` | Metadata |
| `.algorithm(a)` | How the policy's own rules combine: `deny-overrides` (default), `allow-overrides`, `first-match`, `highest-priority` |
| `.target({ actions, resources, roles })` | Skip the policy entirely unless the request matches |
| `.rule(id, r => ...)` | Add a rule inline |
| `.addRule(rule)` | Add a rule built separately with `defineRule` |
| `.build()` | Produce the `Policy` object |

### Rule builder

| Method | What it does |
|---|---|
| `.allow()` / `.deny()` | Effect (a rule must state one) |
| `.on(...actions)` | Actions the rule covers; `'*'` for any |
| `.of(...resources)` | Resource types the rule covers; `'*'` for any |
| `.forScope(...scopes)` | Limit to these scopes; omit for all |
| `.priority(n)` | Ordering for `first-match` / `highest-priority` |
| `.when(w => ...)` | Conditions, ANDed |
| `.whenAny(w => ...)` | Conditions, ORed |
| `.build()` | Produce the `Rule` object |

### Condition reference

`When` is the `w` in `.when(w => ...)`. Chained calls AND together.

| Method | What it does |
|---|---|
| `.check(field, op, value)` | Compare any dot-path (`subject.attributes.tier`, `environment.hour`, ...) |
| `.attr(path, op, value)` | Subject attribute — shorthand for `subject.attributes.<path>` |
| `.resourceAttr(path, op, value)` | Resource attribute — shorthand for `resource.attributes.<path>` |
| `.env(path, op, value)` | Environment attribute — shorthand for `environment.<path>` |
| `.role(id)` / `.roles(...ids)` | Subject holds this role / any of these |
| `.scope(id)` / `.scopes(...ids)` | Request is in this scope / any of these |
| `.isOwner(field?)` | Resource's owner field equals the subject's id; defaults to `resource.attributes.ownerId` |
| `.resourceType(...types)` | Resource type is one of these |
| `.and(w => ...)` | Nested AND group |
| `.or(w => ...)` | Nested OR group |
| `.not(w => ...)` | Negated group |

There is no `.check(fn)` — conditions are declarative data, not closures, so the
compiled production table can represent them.

---

## 5. Storage Adapters

### Memory (dev / tests)

```ts
import { IamMemoryAdapter } from '@gentleduck/iam/adapters/memory'

const adapter = new IamMemoryAdapter({
  policies: [...policies],
  roles: [...roles],
})
```

### Drizzle (prod — PG / MySQL / SQLite)

```ts
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { drizzle } from 'drizzle-orm/node-postgres'
import { iamPolicies, iamRoles, iamAssignments, iamSubjectAttrs } from './schema'

const db = drizzle(pool)

const adapter = new IamDrizzleAdapter({
  db,
  tables: { iamPolicies, iamRoles, iamAssignments, iamSubjectAttrs },
})
```

Add to your Drizzle schema:

```ts
// schema.ts
export { iamPolicies, iamRoles, iamAssignments, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/pg'
// MySQL:  '@gentleduck/iam/adapters/drizzle/mysql'
// SQLite: '@gentleduck/iam/adapters/drizzle/sqlite'
```

### Redis

```ts
import { IamRedisAdapter } from '@gentleduck/iam/adapters/redis'
import { Redis } from 'ioredis'

const adapter = new IamRedisAdapter({ redis: new Redis(process.env.REDIS_URL!) })
```

### HTTP (remote adapter — call a policy service)

```ts
import { IamHttpAdapter } from '@gentleduck/iam/adapters/http'

const adapter = new IamHttpAdapter({
  baseUrl: 'https://policy-service.internal',
  allowedHosts: ['policy-service.internal'],
  headers: { Authorization: `Bearer ${process.env.IAM_SERVICE_TOKEN}` },
})
```

---

## 6. Create the Engine

```ts
// src/engine.ts
import { iam } from './iam'
import { adapter } from './adapter'

export const engine = iam.createEngine({
  adapter,
  defaultEffect: 'deny',          // fail-closed
  mode: 'production',             // can() returns boolean (not Decision object)
  cacheTTL: 60,                   // seconds; 0 to disable
  maxCacheSize: 1000,
  policyCombine: 'and',           // every matching policy must allow
})

// or construct directly:
import { IamEngine } from '@gentleduck/iam'
const engine = new IamEngine({ adapter, defaultEffect: 'deny' })
```

---

## 7. Evaluate Permissions

```ts
// Simple boolean — production mode
const canUpdate = await engine.can(
  userId,        // subjectId: string
  'update',      // action (typed)
  {
    type: 'post',
    id: post.id,
    attributes: { authorId: post.authorId, status: post.status },
  },
)

if (!canUpdate) return Response.json({ error: 'Forbidden' }, { status: 403 })
```

### Development mode — rich Decision object

```ts
// `attributes` is required on IResource - pass `{}` when there are none.
const decision = await engine.check(userId, 'delete', { type: 'post', id: postId, attributes: {} })
// decision.allowed:   boolean
// decision.effect:    'allow' | 'deny'
// decision.reason:    string        — singular; one line saying why
// decision.policy?:   string        — id of the deciding policy, if any
// decision.rule?:     IRule         — the deciding rule, if any
// decision.duration:  number        — ms spent evaluating
// decision.timestamp: number        — Unix ms
// decision.failure?:  'input' | 'resolution' | 'evaluation'
```

`failure` is the one to branch on: it is set only when the deny came from the
engine breaking rather than from a policy saying no, so it is how you answer
`503` for an adapter outage and `403` for a real denial. It is absent on every
ordinary decision.

There is no `decision.reasons` array and no `decision.trace` — for the full
evaluation trace, call `explain()`.

### Explain (audit trail)

```ts
const trace = await engine.explain(userId, 'publish', {
  type: 'post',
  id: postId,
  attributes: { status: 'ready', authorId: userId },
})

trace.decision.allowed  // boolean — the outcome lives on `decision`
trace.request           // { action, resourceType, resourceId?, scope? }
trace.subject           // { id, roles, scopedRolesApplied, attributes }
trace.policies          // IPolicyTrace[] — every policy consulted, in order
trace.summary           // plain-text human-readable rendering
```

Each entry in `trace.policies` carries `policyId`, `policyName`, `algorithm`,
`targetMatch`, `result`, `reason`, `rules`, and — when one rule decided it —
`decidingRuleId` / `decidingRule`. To list the policies that actually applied:

```ts
const applied = trace.policies.filter((p) => p.targetMatch)
```

> `trace.summary` interpolates policy ids, subject ids and role ids verbatim,
> and those can be operator- or request-supplied. If you render it into HTML,
> escape it yourself — the explain pipeline never escapes for a specific target.

### Batch check

`checks()` describes each check with a `resource` **string** plus an optional
`resourceId` — not a resource object:

```ts
const checks = iam.checks([
  { action: 'read',   resource: 'post',    resourceId: postId },
  { action: 'update', resource: 'comment', resourceId: commentId },
  { action: 'delete', resource: 'post',    resourceId: postId, scope: 'org-1' },
])

const results = await engine.permissions(userId, checks)
```

`permissions()` returns a **keyed map**, not an array — the key format is
`[@scope:]action:resource[:resourceId]`, the same one `iamBuildPermissionKey`
produces:

```ts
results[`read:post:${postId}`]              // boolean
results[`update:comment:${commentId}`]      // boolean
results[`@org-1:delete:post:${postId}`]     // boolean — note the `@` scope marker
```

In production mode the values are plain booleans; in development mode you get
the full typed `IamClient.PermissionMap`. Batches over 1024 checks throw — an
oversized batch is a caller bug, not a fail-closed deny.

---

## 8. Manage Roles & Policies at Runtime

```ts
const admin = engine.admin

// Policies
await admin.savePolicy(postOwnerPolicy)
await admin.deletePolicy('post-owner')
const policies = await admin.listPolicies()

// Roles
await admin.saveRole(editorRole)
const role = await admin.getRole('editor')

// Subject role assignment
await admin.assignRole(userId, 'editor')                 // global
await admin.assignRole(userId, 'editor', 'org:acme')     // scoped

await admin.revokeRole(userId, 'editor')

// Subject attributes
await admin.setAttributes(userId, {
  userId,
  orgId: 'org:acme',
  tier: 'pro',
})
const attrs = await admin.getAttributes(userId)
```

---

## 9. Cache Invalidation

Cache invalidation is automatic when you use `admin.*` methods.
For distributed deployments, wire an invalidator:

```ts
import { createIamRedisInvalidator } from '@gentleduck/iam/invalidators/redis'
import { Redis } from 'ioredis'

// One client, not a publisher/subscriber pair - the invalidator owns both
// sides of the channel itself.
const invalidator = createIamRedisInvalidator({
  client: new Redis(process.env.REDIS_URL!),
  // Sign every envelope. Without it the invalidator falls back to unsigned
  // messages and warns once: anyone with PUBLISH rights on the channel can
  // wipe your caches. Set it in production.
  secret: process.env.IAM_INVALIDATE_SECRET!,
  // Multi-tenant on shared Redis: scopes the channel to
  // `duck-iam:invalidate:tenant:<id>` so tenant A cannot flush tenant B.
  // tenantId: 'acme',
  onPublishError: (err, channel) => alert.warn({ err, channel }),
  onSubscribeError: (err, channel) => alert.error({ err, channel }),
})

const engine = iam.createEngine({
  adapter,
  defaultEffect: 'deny',
  invalidator,   // all instances subscribe; policy save on node A clears cache on nodes B+C
})
```

`createIamRedisInvalidator` is a **factory**, not a class. `IamRedisInvalidator`
is the type-only namespace holding its `IConfig` and `IPubSubLike` — there is no
constructor to call with `new`. The subpath is
`@gentleduck/iam/invalidators/redis`; `@gentleduck/iam/adapters/redis` is the
storage adapter, a different thing.

Wire `onSubscribeError` even if you skip `onPublishError`: a failed publish loses
one event, a failed subscribe loses every future one.

---

## 10. Snapshot Export / Import (GitOps)

```ts
// Export current policy set
const snapshot = await engine.admin.export()
await fs.writeFile('iam-snapshot.json', JSON.stringify(snapshot, null, 2))

// Import into another environment
const data = JSON.parse(await fs.readFile('iam-snapshot.json', 'utf8'))
await engine.admin.import(data, { mode: 'replace' })  // 'merge' | 'replace'
```

---

## 11. Server Adapters

### Hono middleware

```ts
import { Hono } from 'hono'
import { engine } from './engine'

const app = new Hono()

// Inline guard
app.put('/posts/:id', async (c) => {
  const userId = c.get('userId')      // set by your auth middleware
  const post   = await db.posts.find(c.req.param('id'))

  const allowed = await engine.can(userId, 'update', {
    type: 'post',
    id: post.id,
    attributes: { authorId: post.authorId },
  })
  if (!allowed) return c.json({ error: 'Forbidden' }, 403)

  // proceed
})
```

### Generic permission middleware factory

```ts
function requirePermission(action: string, resource: string) {
  return async (req, res, next) => {
    const userId = req.user.id
    const allowed = await engine.can(userId, action, { type: resource, id: req.params.id })
    if (!allowed) return res.status(403).json({ error: 'Forbidden' })
    next()
  }
}

router.delete('/posts/:id', requirePermission('delete', 'post'), deletePostHandler)
```

---

## 12. Integrate with duck-auth

duck-iam and duck-auth are independent packages — wire them together via events or middleware.

```ts
import { auth } from './auth'     // AuthEngine
import { engine } from './engine' // IamEngine

// After resolving session, check IAM before the route runs
async function authzMiddleware(req, res, next) {
  const result = await auth.resolveSession({ headers: req.headers })
  if (!result) return res.status(401).json({ error: 'Unauthorized' })

  const { identity } = result
  const allowed = await engine.can(identity!.id, req.iamAction, req.iamResource)
  if (!allowed) return res.status(403).json({ error: 'Forbidden' })

  req.identity = identity
  next()
}

// Sync role on sign-in (link duck-auth identity to duck-iam role)
auth.events.on('signin.success', async ({ session }) => {
  const identity = await auth.identities.findById(session.identityId)
  const orgId = identity?.profile?.orgId
  if (orgId) {
    await engine.admin.assignRole(session.identityId, 'editor', `org:${orgId}`)
  }
})
```

### Orgs: duck-auth `storage.orgs` vs duck-iam scopes

The two packages use org IDs independently:

| | duck-auth | duck-iam |
|---|---|---|
| Concept | `AuthOrg.IStore<OrgMeta>` — org membership + metadata | `scope` string — constrains role assignment |
| Format | any string (e.g. `'org:acme'`) | same string as the scope arg |
| Store | `auth.stores.orgs` — your implementation | `engine.admin.assignRole(userId, role, scope)` |

**Key facts:**

- `authDrizzlePgStorage` does **not** expose an `orgs` store. Implement `AuthOrg.IStore<OrgMeta>`
  yourself using your org table and pass it as `storage.orgs` in `createAuth`.
- duck-iam does not read from `auth.stores.orgs`. Org membership in auth and scoped role
  assignments in IAM are separate records — they just share the same org ID string.
- To keep them in sync, listen to auth org events and mirror into IAM:

```ts
auth.events.on('org.member.added', async ({ orgId, identityId, role }) => {
  // mirror the org membership as a scoped IAM role
  await engine.admin.assignRole(identityId, role, `org:${orgId}`)
})

auth.events.on('org.member.removed', async ({ orgId, identityId }) => {
  // Revoke all scoped roles for this org. The admin facet has no
  // list-assignments method - read the subject's scoped grants from the
  // adapter, which is the layer that owns assignment rows.
  const scoped = await adapter.getSubjectScopedRoles(identityId)
  await engine.admin.revokeRoles(
    scoped
      .filter((g) => g.scope === `org:${orgId}`)
      .map((g) => ({ subjectId: identityId, roleId: g.role, scope: g.scope })),
  )
})
```

`revokeRoles` takes the whole batch at once, so an adapter with a set-based
delete does it in one statement; adapters without one fall back to a loop.

- If you do not use `auth.orgs` at all (e.g. org data lives in a separate service),
  omit `storage.orgs` from `createAuth`. duck-iam still works; just use scopes directly.

---

## 13. Validation

Both validators return `{ valid, issues }` — there is no `ok` and no `errors`.
Getting this wrong is quiet and expensive: `if (!result.ok)` is `true` for every
*valid* policy, because `ok` is always `undefined`.

```ts
import type { IamValidate } from '@gentleduck/iam/core/validate'

// Validate an untrusted policy (from DB, API, user upload)
const result = iam.validatePolicy(untrustedInput)
if (!result.valid) {
  console.error(result.issues)
}

// Validate a role set for circular inheritance, duplicate IDs, etc.
const roleResult = iam.validateRoles(roles)
if (!roleResult.valid) {
  console.error(roleResult.issues)
}
```

`valid` is `false` only when there is at least one **error**-level issue;
warnings never flip it. Each issue carries:

| Field | Meaning |
| --- | --- |
| `type` | `'error'` blocks usage, `'warning'` is informational |
| `code` | machine-readable `ValidationCode` — branch on this, not on `message` |
| `message` | human-readable description |
| `roleId?` | set by role validation |
| `path?` | dot-path into the offending field, set by policy validation |

So to treat warnings as non-blocking but still surface them:

```ts
const errors = result.issues.filter((i) => i.type === 'error')
const warnings = result.issues.filter((i) => i.type === 'warning')
```

---

## Tips

- **`mode: 'production'`** returns `boolean` from `can()` — zero overhead, no Decision object allocation. Use `mode: 'development'` in dev/tests to get `reasons` + `trace`.
- **`policyCombine: 'and'`** is default (every applicable policy must allow). The only other values are `'allow-overrides'` (any applicable policy allowing is enough) and `'first-applicable'` (the first policy that is not NotApplicable decides; development mode only). There is no `'or'` — the engine now throws on an unrecognised value rather than falling through to the most permissive branch.
- **`defaultEffect: 'deny'`** is fail-closed. Never set `defaultEffect: 'allow'` in production without the `allowFailOpen: true` flag — the engine constructor refuses it to prevent accidental fail-open deployments.
- **Cache TTL**: `cacheTTL: 0` does **not** disable caching. Entries expire on a
  strict `Date.now() > expiresAt`, so a `0` TTL still serves a cached value to
  every read that lands in the same millisecond as the write. It is close
  enough for tests; it is not a consistency guarantee. To be certain a read is
  fresh, invalidate explicitly (`engine.cache.invalidateSubject(id)`). For
  prod, 30–60s TTL with a Redis invalidator is the sweet spot.
- **Typed dot-paths**: passing `context: {} as unknown as AppContext` to `createIam` enables IntelliSense on `.env()` and `.attr()` condition paths. No runtime cost.
- **GitOps policies**: export your policy snapshot on every prod deploy and check it into git. Use `import({ mode: 'merge' })` on startup to keep the DB in sync without wiping runtime-assigned subject data.
- **Multi-tenant scoping**: assign roles with a `scope` argument (`assignRole(userId, 'editor', 'org:acme')`). The engine evaluates scoped roles only when the request carries a matching scope.
- **RBAC-only?** Skip `definePolicy`. Define roles, assign them, and `can()` just reads from the merged RBAC rule set. You can add ABAC policies later without changing how you call `can()`.
