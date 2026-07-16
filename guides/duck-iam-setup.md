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

interface AppContext {
  user: { id: string; orgId: string; tier: 'free' | 'pro' }
  env: { region: string }
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

Policies let you express attribute-based rules beyond simple role grants.
Rules combine with `all()` (AND) / `any()` (OR).

```ts
// src/policies.ts
import { iam } from './iam'

// Only the author OR an admin can update a post
export const postOwnerPolicy = iam.definePolicy('post-owner')
  .allow('update', 'post')
  .when(
    iam.when()
      .any(
        (w) => w.check((ctx) => ctx.subject.attributes.userId === ctx.resource.attributes.authorId),
        (w) => w.hasRole('admin'),
      ),
  )
  .build()

// Only allow publish on posts that are in 'ready' state
export const publishGatePolicy = iam.definePolicy('publish-gate')
  .allow('publish', 'post')
  .when(
    iam.when()
      .attr('resource.status', 'eq', 'ready')
      .hasRole('editor'),
  )
  .build()

// Multi-tenant: user can only act within their own org scope
export const orgScopePolicy = iam.definePolicy('org-scope')
  .allow('create', 'post')
  .allow('update', 'post')
  .when(
    iam.when()
      .env('user.orgId', 'eq', 'org:acme')   // typed dot-path via AppContext
      .hasRole('editor'),
  )
  .build()

export const policies = [postOwnerPolicy, publishGatePolicy, orgScopePolicy]
```

### Condition reference

| Method | What it does |
|---|---|
| `.attr(path, op, value)` | Compare a dot-path on resource/subject attributes |
| `.env(path, op, value)` | Compare against the context (your `AppContext`) |
| `.resourceAttr(path, op, value)` | Shorthand for resource attribute check |
| `.check(fn)` | Arbitrary function — receives full context |
| `.hasRole(roleId)` | Subject holds this role |
| `.all(...conditions)` | AND |
| `.any(...conditions)` | OR |
| `.not(condition)` | Negate |

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
export { iamPolicies, iamRoles, iamAssignments, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/schema/pg'
// MySQL:  '@gentleduck/iam/adapters/drizzle/schema/mysql'
// SQLite: '@gentleduck/iam/adapters/drizzle/schema/sqlite'
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
const decision = await engine.check(userId, 'delete', { type: 'post', id: postId })
// decision.allowed: boolean
// decision.reasons: string[]  — which rules matched
// decision.trace:   ...       — full evaluation trace
```

### Explain (audit trail)

```ts
const trace = await engine.explain(userId, 'publish', {
  type: 'post',
  id: postId,
  attributes: { status: 'ready', authorId: userId },
})
console.log(trace.allowed, trace.matchedPolicies)
```

### Batch check

```ts
const checks = iam.checks([
  { action: 'read',   resource: { type: 'post',    id: postId } },
  { action: 'update', resource: { type: 'comment', id: commentId } },
  { action: 'delete', resource: { type: 'post',    id: postId } },
])

const results = await engine.permissions(userId, checks)
// results[0].allowed, results[1].allowed, results[2].allowed
```

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
import { IamRedisInvalidator } from '@gentleduck/iam/adapters/redis'
import { Redis } from 'ioredis'

const publisher  = new Redis(process.env.REDIS_URL!)
const subscriber = new Redis(process.env.REDIS_URL!)

const invalidator = new IamRedisInvalidator({ publisher, subscriber })

const engine = iam.createEngine({
  adapter,
  defaultEffect: 'deny',
  invalidator,   // all instances subscribe; policy save on node A clears cache on nodes B+C
})
```

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
  // revoke all scoped roles for this org
  const assignments = await engine.admin.listAssignments(identityId)
  for (const a of assignments.filter((x) => x.scope === `org:${orgId}`)) {
    await engine.admin.revokeRole(identityId, a.role, a.scope)
  }
})
```

- If you do not use `auth.orgs` at all (e.g. org data lives in a separate service),
  omit `storage.orgs` from `createAuth`. duck-iam still works; just use scopes directly.

---

## 13. Validation

```ts
import { IamValidate } from '@gentleduck/iam/core/validate'

// Validate an untrusted policy (from DB, API, user upload)
const result = iam.validatePolicy(untrustedInput)
if (!result.ok) {
  console.error(result.errors)  // typed validation errors
}

// Validate a role set for circular inheritance, duplicate IDs, etc.
const roleResult = iam.validateRoles(roles)
if (!roleResult.ok) {
  console.error(roleResult.errors)
}
```

---

## Tips

- **`mode: 'production'`** returns `boolean` from `can()` — zero overhead, no Decision object allocation. Use `mode: 'development'` in dev/tests to get `reasons` + `trace`.
- **`policyCombine: 'and'`** is default (all policies must allow). Switch to `'or'` for "any policy grants = allow" semantics — watch out with ABAC policies that have broad deny rules.
- **`defaultEffect: 'deny'`** is fail-closed. Never set `defaultEffect: 'allow'` in production without the `allowFailOpen: true` flag — the engine constructor refuses it to prevent accidental fail-open deployments.
- **Cache TTL**: `cacheTTL: 0` disables caching entirely. Use for ultra-low-latency tests or when you need fully consistent reads on every check. For prod, 30–60s TTL with a Redis invalidator is the sweet spot.
- **Typed dot-paths**: passing `context: {} as unknown as AppContext` to `createIam` enables IntelliSense on `.env()` and `.attr()` condition paths. No runtime cost.
- **GitOps policies**: export your policy snapshot on every prod deploy and check it into git. Use `import({ mode: 'merge' })` on startup to keep the DB in sync without wiping runtime-assigned subject data.
- **Multi-tenant scoping**: assign roles with a `scope` argument (`assignRole(userId, 'editor', 'org:acme')`). The engine evaluates scoped roles only when the request carries a matching scope.
- **RBAC-only?** Skip `definePolicy`. Define roles, assign them, and `can()` just reads from the merged RBAC rule set. You can add ABAC policies later without changing how you call `can()`.
