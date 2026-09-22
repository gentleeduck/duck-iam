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

// The same unions `createIam` derives, named so you can write them into your
// own signatures. Used by §11's middleware factory.
export type Action = 'create' | 'read' | 'update' | 'delete' | 'publish' | 'archive'
export type ResourceType = 'post' | 'comment' | 'user' | 'org' | 'invoice'
export type RoleId = 'viewer' | 'editor' | 'admin' | 'billing'
export type Scope = 'org:acme' | 'org:beta'
```

`iam` now exposes typed builders:

```ts
iam.defineRole('viewer')          // TRole constrained
iam.definePolicy('my-policy')     // PolicyBuilder; the id is a free string
iam.defineRule('my-rule')         // RuleBuilder, for rules shared across policies
iam.when()                        // reusable condition group
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
| `.allow()` / `.deny()` | Effect. `allow` is the default, so `.deny()` is the one you must say out loud |
| `.on(...actions)` | Actions the rule covers; `'*'` for any |
| `.of(...resources)` | Resource types the rule covers; `'*'` for any |
| `.forScope(...scopes)` | Limit to these scopes; omit for all |
| `.priority(n)` | Ordering for `first-match` / `highest-priority` |
| `.when(w => ...)` | Conditions, ANDed |
| `.whenAny(w => ...)` | Conditions, ORed |
| `.build()` | Produce the `Rule` object |

`build()` refuses a rule where none of effect, action, resource, scope or
condition was set: the defaults are `allow` on `'*' × '*'` with no conditions,
so silence would compile into the broadest possible grant. `.desc()`,
`.priority()` and `.meta()` do not count as configuring it.

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

Pick one. Each block below is the whole of `src/adapter.ts`, which is what §6
imports `adapter` from.

### Memory (dev / tests)

```ts
// src/adapter.ts
import { IamMemoryAdapter } from '@gentleduck/iam/adapters/memory'
import { policies } from './policies'
import { roles } from './roles'

export const adapter = new IamMemoryAdapter({
  policies,
  roles,
  // Optional seed, so a dev run has grants without an admin call.
  assignments: { 'user-1': ['editor'] },
  attributes: { 'user-1': { orgId: 'acme', tier: 'pro' } },
})
```

`assignments` holds unscoped role IDs only — the seed has no way to express a
scope, so use `admin.assignRole(id, role, scope)` for those. Seeding a role the
`roles` array does not define throws, the same refusal `assignRole` applies.

### Drizzle (prod — PG / MySQL / SQLite)

```ts
// src/adapter.ts
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/pg'
import { and, eq, isNull, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export const adapter = new IamDrizzleAdapter({
  db: drizzle(pool),
  // The keys are the adapter's own — `attrs`, not `iamSubjectAttrs`. Shorthand
  // property names here would build an object the adapter reads nothing from.
  tables: { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles },
  // drizzle's own operators, passed straight through. `eq` and `and` are
  // required; omit them and the adapter warns that it is running on a degraded
  // path. `isNull` gates `updateAssignmentScope`, `or` collapses
  // `revokeRoleMany` into one DELETE.
  ops: { and, eq, isNull, or },
})
```

The dialect subpaths export **schema only** — the adapter class is
dialect-neutral, and nothing inspects `db` to work out which dialect you are on.
Switching is two changes, not one:

- MySQL: import the tables from `@gentleduck/iam/adapters/drizzle/mysql` **and**
  pass `dialect: 'mysql'`.
- SQLite: import from `@gentleduck/iam/adapters/drizzle/sqlite` **and** pass
  `dialect: 'sqlite'` plus `json: 'string'` — every payload column is `TEXT`.

`dialect` defaults to `'pg'` and `json` to `'native'`, which is why Postgres
needs neither. Re-export the tables from your own schema module if drizzle-kit
generates migrations from it:

```ts
// schema.ts
export { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/pg'
```

### Redis

```ts
// src/adapter.ts
import { IamRedisAdapter } from '@gentleduck/iam/adapters/redis'
import { Redis } from 'ioredis'

// The option is `client`, and it is the only required one.
export const adapter = new IamRedisAdapter({
  client: new Redis(process.env.REDIS_URL!),
  keyPrefix: 'iam:',
})
```

The adapter sets no TTL on any key it writes. Nothing expires on its own.

### HTTP (remote adapter — call a policy service)

```ts
// src/adapter.ts
import { IamHttpAdapter } from '@gentleduck/iam/adapters/http'

export const adapter = new IamHttpAdapter({
  // Paths append to `baseUrl` verbatim, so a mount prefix here carries through.
  baseUrl: 'https://policy-service.internal',
  allowedHosts: ['policy-service.internal'],
  headers: { Authorization: `Bearer ${process.env.IAM_SERVICE_TOKEN}` },
})
```

`headers` also accepts an async function, for a token you have to mint per
request. Omitting `allowedHosts` warns once — a DNS name pointing at a private
address is constrained by nothing else.

---

## 6. Create the Engine

```ts
// src/engine.ts
import { iam } from './iam'
import { adapter } from './adapter'

export const engine = iam.createEngine({
  adapter,
  defaultEffect: 'deny',          // fail-closed; 'allow' needs allowFailOpen: true
  mode: 'production',             // check() returns boolean, not a Decision object
  cacheTTL: 60,                   // seconds; 0 means do not cache
  maxCacheSize: 1000,             // subject-cache capacity only
  policyCombine: 'and',           // every applicable policy must allow
})
```

Every one of those is already the default — the block spells them out because
they are the settings you will want to reconsider, not because they need
setting. `new IamEngine(config)` from `@gentleduck/iam` takes the same config
and is what `createEngine` wraps; the typed builder is the only reason to prefer
`iam.createEngine`.

The config is validated in the constructor, so a bad one is a failed start
rather than a surprise on the first request. `policyCombine` outside the three
valid values throws, as does `mode: 'production'` with
`policyCombine: 'first-applicable'`.

**Set `mode: 'development'` for the next two sections.** `check()` returns a
bare boolean and `explain()` throws on a production engine — `explain` is
additionally a type error there, because its `this` parameter is typed to a
development engine.

---

## 7. Evaluate Permissions

```ts
// Simple boolean — same return type in both modes
const canUpdate = await engine.can(
  userId,        // subjectId: string, 1–1024 chars; anything else is a silent false
  'update',      // action (typed)
  {
    type: 'post',
    id: post.id,
    // `ownerId` because §4's rule used `.isOwner()`, which reads
    // `resource.attributes.ownerId` unless you name another field.
    attributes: { ownerId: post.ownerId, status: post.status },
  },
)

if (!canUpdate) return Response.json({ error: 'Forbidden' }, { status: 403 })
```

### Development mode — rich Decision object

Needs an engine built with `mode: 'development'`. In production `check()` is
`can()` with a wider return type, and the fields below do not exist.

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

Development only, and read-only: `explain()` applies `beforeEvaluate` but fires
none of `afterEvaluate` / `onDeny` / `onError`.

```ts
const trace = await engine.explain(userId, 'publish', {
  type: 'post',
  id: postId,
  attributes: { status: 'ready', ownerId: userId },
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

`scope` is typed to the `scopes` you declared in §2, so it is `'org:acme'` here
and not some free string.

```ts
const checks = iam.checks([
  { action: 'read',   resource: 'post',    resourceId: postId },
  { action: 'update', resource: 'comment', resourceId: commentId },
  { action: 'delete', resource: 'post',    resourceId: postId, scope: 'org:acme' },
])

const results = await engine.permissions(userId, checks)
```

`permissions()` returns a **keyed map**, not an array. The key format is
`[@scope:]action:resource[:resourceId]`, and each segment has its `:`, `\` and
leading `@` backslash-escaped — which matters the moment a scope contains a
colon, as `'org:acme'` does. Build keys with `iamBuildPermissionKey` rather than
by hand:

```ts
import { iamBuildPermissionKey } from '@gentleduck/iam'

results[iamBuildPermissionKey('read', 'post', postId)]                   // `read:post:<id>`
results[iamBuildPermissionKey('update', 'comment', commentId)]           // `update:comment:<id>`
results[iamBuildPermissionKey('delete', 'post', postId, 'org:acme')]     // `@org\:acme:delete:post:<id>`
```

The `@` marker is what keeps a three-segment key unambiguous: without it
`('read','doc','42')` and `('doc','42',undefined,'read')` both produce
`read:doc:42`, and one check answers for the other.

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

// Subject attributes. These are what `.attr()` conditions read, so `orgId` here
// is the plain `'acme'` §4's org-scope rule compares against - not the
// `'org:acme'` scope string, which is a different vocabulary.
await admin.setAttributes(userId, {
  orgId: 'acme',
  tier: 'pro',
})
const attrs = await admin.getAttributes(userId)
```

---

## 9. Cache Invalidation

Cache invalidation is automatic when you use `admin.*` methods.
For distributed deployments, wire an invalidator:

```ts
import { createIamRedisInvalidator, type IamRedisInvalidator } from '@gentleduck/iam/invalidators/redis'
import { Redis } from 'ioredis'

// `client` is one object, but it needs TWO connections behind it: Redis refuses
// every other command on a connection that has subscribed, so publishing
// through the subscriber fails. Passing a single `new Redis()` gets you an
// invalidator that receives and never sends.
const pub = new Redis(process.env.REDIS_URL!)
const sub = new Redis(process.env.REDIS_URL!)

const client: IamRedisInvalidator.IPubSubLike = {
  publish: (channel, message) => pub.publish(channel, message),
  subscribe: async (channel, handler) => {
    sub.on('message', (received, message) => {
      if (received === channel) handler(message)
    })
    // Awaited, so a NOAUTH or a bad ACL reaches onSubscribeError instead of vanishing.
    await sub.subscribe(channel)
  },
  unsubscribe: (channel) => sub.unsubscribe(channel),
}

const invalidator = createIamRedisInvalidator({
  client,
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

// Every engine on the channel receives the event: a policy save on node A
// clears the caches on B and C. A received event is never re-published.
engine.setInvalidator(invalidator)
```

`invalidator` is also a `createEngine` config key. Prefer `setInvalidator` when
the engine is built at module scope and the Redis connections only exist at
startup, which is the ordinary shape.

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
import fs from 'node:fs/promises'
import { engine } from './engine'

// Export the current policy and role set
const snapshot = await engine.admin.export()
await fs.writeFile('iam-snapshot.json', JSON.stringify(snapshot, null, 2))

// Import into another environment. 'merge' is the default and saves each entry;
// 'replace' first deletes every policy and role the snapshot does not name.
const data = JSON.parse(await fs.readFile('iam-snapshot.json', 'utf8'))
await engine.admin.import(data, { mode: 'replace' })
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
    attributes: { ownerId: post.ownerId },
  })
  if (!allowed) return c.json({ error: 'Forbidden' }, 403)

  // proceed
})
```

### Generic permission middleware factory

A factory like this trades the typed vocabulary for `string`, so nothing catches
a typo in the action or the resource type any more. It also cannot load the row,
so it only expresses rules that need no resource attributes — `attributes` is
required on `IResource`, and `{}` is the honest value for "I have none", not a
field to leave out.

```ts
import type { Action, ResourceType } from './iam'
import { engine } from './engine'

function requirePermission(action: Action, resource: ResourceType) {
  return async (req, res, next) => {
    const userId = req.user.id
    const allowed = await engine.can(userId, action, {
      type: resource,
      id: req.params.id,
      attributes: {},
    })
    if (!allowed) return res.status(403).json({ error: 'Forbidden' })
    next()
  }
}

router.delete('/posts/:id', requirePermission('delete', 'post'), deletePostHandler)
```

Do not reach for the string `'unknown'` as a "matches nothing" action or
resource type. The engine reserves it: it is refused up front with
`failure: 'input'`, which also means a resource type genuinely named `unknown`
can never be granted.

---

## 12. Integrate with duck-auth

duck-iam and duck-auth are independent packages — wire them together via events or middleware.

```ts
import { adapter } from './adapter' // the IAM storage adapter from §5
import { auth } from './auth'       // AuthEngine
import { engine } from './engine'   // IamEngine
import type { RoleId } from './iam'

// After resolving session, check IAM before the route runs.
async function authzMiddleware(req, res, next) {
  // `resolveSession(req, opts?)` takes a Fetch `Headers`, so on a Node-style
  // `req.headers` you build one first. It answers
  // `{ session, identity, anomaly? } | null`; null when there is no token.
  const headers = new Headers()
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === 'string') headers.set(k, v)
  }
  const result = await auth.resolveSession({ headers })
  // `identity` is null on an anonymous session, so check it, not just `result`.
  if (!result?.identity) return res.status(401).json({ error: 'Unauthorized' })

  const { identity } = result
  const allowed = await engine.can(identity.id, req.iamAction, req.iamResource)
  if (!allowed) return res.status(403).json({ error: 'Forbidden' })

  req.identity = identity
  next()
}

// Sync a role on sign-in. The `signin.success` payload is
// `{ identity, factors }` - the identity is already there, so no second lookup.
auth.events.on('signin.success', async ({ identity }) => {
  const orgId = identity.profile?.orgId
  if (orgId) {
    await engine.admin.assignRole(identity.id, 'editor', `org:${orgId}`)
  }
})
```

A scope built at runtime like `` `org:${orgId}` `` is not assignable to the
`Scope` union §2 declared. Either declare the tenants you actually have, or omit
`scopes` from `createIam` — an empty `scopes` array widens `TScope` to `string`
and every scope is accepted. Declaring two example scopes and then assigning a
third is the mistake this line exists to point at.

### Orgs: duck-auth `stores.orgs` vs duck-iam scopes

The two packages use org IDs independently:

| | duck-auth | duck-iam |
|---|---|---|
| Concept | `Org.Store<OrgMeta>` — org membership + metadata | `scope` string — constrains role assignment |
| Format | any string (e.g. `'acme'`) | the scope arg, e.g. `'org:acme'` |
| Reached through | `auth.orgs`, the facet over the store; `null` when no store was passed | `engine.admin.assignRole(userId, role, scope)` |

`authDrizzlePgStorage` does **not** provide an `orgs` store. Implement
`Org.Store<OrgMeta>` against your own org table and pass it as `stores.orgs` in
`createAuth` — the key is `stores`, not `storage`, and the config lands on
`auth.cfg.stores.orgs`.

duck-iam does not read from it. Org membership in auth and scoped role
assignments in IAM are separate records that happen to share an org ID string,
so nothing keeps them in step for you.

**duck-auth emits no org events.** There is no `org.member.added` or
`org.member.removed` on the bus, so the mirroring has to happen at your own call
site — wherever you call `auth.orgs.addMember` / `removeMember`:

```ts
async function addToOrg(orgId: string, identityId: string, role: RoleId) {
  await auth.orgs?.addMember({ orgId, identityId, roles: [role] })
  await engine.admin.assignRole(identityId, role, `org:${orgId}`)
}

async function removeFromOrg(orgId: string, identityId: string) {
  await auth.orgs?.removeMember(orgId, identityId)
  // Revoke every scoped role for this org. The admin facet has no
  // list-assignments method - read the subject's scoped grants from the
  // adapter, which is the layer that owns assignment rows.
  const scoped = await adapter.getSubjectScopedRoles(identityId)
  await engine.admin.revokeRoles(
    scoped
      .filter((g) => g.scope === `org:${orgId}`)
      .map((g) => ({ subjectId: identityId, roleId: g.role, scope: g.scope })),
  )
}
```

`getSubjectScopedRoles` is optional on the adapter contract, though all six
shipped adapters implement it. `revokeRoles` takes the whole batch at once, so
an adapter with a set-based delete does it in one statement; adapters without
one fall back to a loop.

If you do not use `auth.orgs` at all — org data lives in a separate service, say
— omit `stores.orgs` from `createAuth`. duck-iam still works; use scopes
directly.

---

## 13. Validation

Both validators return `{ valid, issues }` — there is no `ok` and no `errors`.
Getting this wrong is quiet and expensive: `if (!result.ok)` is `true` for every
*valid* policy, because `ok` is always `undefined`.

```ts
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

Neither one throws. `validateRoles` reports a row that is not a role at all —
not an object, no string `id`, no `permissions` array — as an `INVALID_TYPE`
error issue naming its index, so a malformed row comes back as a report rather
than a `TypeError`.

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

- **`mode: 'production'`** is the default. `can()` returns `boolean` in both
  modes; what production drops is `check()`'s `IDecision` and `explain()`. Both
  modes get their verdict from the same compiled table — development
  additionally runs the interpreter and throws if the two disagree, which is why
  a divergence surfaces in dev rather than in prod.
- **`policyCombine: 'and'`** is default (every applicable policy must allow). The only other values are `'allow-overrides'` (any applicable policy allowing is enough) and `'first-applicable'` (the first policy that is not NotApplicable decides; development mode only). There is no `'or'` — the engine now throws on an unrecognised value rather than falling through to the most permissive branch.
- **`defaultEffect: 'deny'`** is fail-closed. Never set `defaultEffect: 'allow'` in production without the `allowFailOpen: true` flag — the engine constructor refuses it to prevent accidental fail-open deployments.
- **Cache TTL**: `cacheTTL: 0` disables caching. Expiry is `Date.now() >=
  expiresAt`, so a `0` TTL entry is already expired when it is read back, and
  the compiled table is rebuilt on every request — correct, and very slow. To
  drop one subject's cached data without turning caching off, call
  `engine.cache.invalidateSubject(id)`. For prod, 30–60s with a Redis
  invalidator. `cacheTTL` is seconds, and a negative or non-finite value throws
  at construction.
- **Typed dot-paths**: passing `context: {} as unknown as AppContext` to `createIam` enables IntelliSense on `.env()` and `.attr()` condition paths. No runtime cost.
- **GitOps policies**: export your policy snapshot on every prod deploy and check it into git. Use `import(snapshot, { mode: 'merge' })` — the default — on startup to keep the DB in sync without wiping runtime-assigned subject data. Both modes validate every policy and role before touching the adapter, so a bad snapshot throws with the store untouched.
- **Past 32 roles**: the compiled fast path stops, but the engine does not. It warns once, falls back to the interpreter, and reports it on `healthCheck()`. It is not a cap on your catalog and it is not a deny.
- **Multi-tenant scoping**: assign roles with a `scope` argument (`assignRole(userId, 'editor', 'org:acme')`). The engine evaluates scoped roles only when the request carries a matching scope.
- **RBAC-only?** Skip `definePolicy`. Define roles, assign them, and `can()` just reads from the merged RBAC rule set. You can add ABAC policies later without changing how you call `can()`.
