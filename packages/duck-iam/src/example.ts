/**
 * duck-iam -- Complete Feature Example
 *
 * This single file walks through every major feature of the library.
 * Run it with: npx tsx src/example.ts
 */

import { createAccessConfig, evaluatePolicy, MemoryAdapter } from './index'

// -- 1. Type-safe configuration ------------------------------------------
//
// Define your domain once. Every builder, check, and engine call is fully
// typed against these string literals -- typos are compile-time errors.

const access = createAccessConfig({
  actions: ['create', 'read', 'update', 'delete', 'publish'] as const,
  resources: ['post', 'comment', 'user'] as const,
  scopes: ['org-1', 'org-2'] as const,
})

// -- 2. Role definitions (RBAC) ------------------------------------------
//
// Roles are the simplest way to grant permissions.
// `inherits` builds a hierarchy without repeating yourself.

const viewer = access
  .defineRole('viewer')
  .name('Viewer')
  .grantRead('post', 'comment') // read:post + read:comment
  .build()

const editor = access
  .defineRole('editor')
  .name('Editor')
  .inherits('viewer') // gets all viewer permissions automatically
  .grant('create', 'post')
  .grant('update', 'post')
  .grant('delete', 'post')
  .build()

// -- 3. Owner-only permissions (ABAC condition on a role) -----------------
//
// `grantWhen` attaches a condition checked at evaluation time.
// `$subject.id` resolves dynamically to the requesting user's id.

const author = access
  .defineRole('author')
  .name('Author')
  .inherits('viewer')
  .grant('create', 'post')
  .grantWhen('update', 'post', (w) => w.isOwner()) // only own posts
  .grantWhen('delete', 'post', (w) => w.isOwner())
  .build()

// -- 4. Wildcard admin ----------------------------------------------------
//
// `*` matches any action/resource -- use for super-admin roles.

const admin = access
  .defineRole('admin')
  .name('Admin')
  .inherits('editor')
  .grantAll('*') // every action on every resource
  .build()

// -- 5. Scoped roles ------------------------------------------------------
//
// Scoped roles only apply when the request scope matches.
// Model multi-tenant permissions (e.g., per-org) this way.

const orgEditor = access
  .defineRole('org-editor')
  .name('Org Editor')
  .scope('org-1') // only active inside org-1
  .grant('create', 'post')
  .grant('update', 'post')
  .build()

// -- 6. ABAC policies (attribute-based rules) -----------------------------
//
// Policies let you write fine-grained rules beyond simple RBAC.
// Each policy has its own combining algorithm for conflict resolution:
//   deny-overrides   -- any deny wins  (safest, default)
//   allow-overrides  -- any allow wins (most permissive)
//   first-match      -- first matching rule decides
//   highest-priority -- highest priority number wins
//
// Here we build a standalone policy and evaluate it directly
// to show the ABAC engine independent of the RBAC system.

const publishPolicy = access
  .policy('publish-control')
  .name('Publish Control')
  .desc('Only senior staff can publish')
  .algorithm('first-match')
  .rule('allow-senior', (r) =>
    r
      .allow()
      .on('publish')
      .of('post')
      .when((w) => w.attr('level', 'gte', 5)),
  )
  .rule('deny-junior', (r) => r.deny().on('publish').of('post'))
  .build()

// Evaluate the policy directly (without the engine)
const seniorReq = {
  subject: { id: 'alice', roles: ['editor'], attributes: { level: 7 } },
  action: 'publish',
  resource: { type: 'post', attributes: {} },
}
const juniorReq = {
  subject: { id: 'bob', roles: ['editor'], attributes: { level: 2 } },
  action: 'publish',
  resource: { type: 'post', attributes: {} },
}

console.log('--- ABAC policy (standalone) ---')
console.log('senior publish:', evaluatePolicy(publishPolicy, seniorReq).allowed) // true
console.log('junior publish:', evaluatePolicy(publishPolicy, juniorReq).allowed) // false

// -- 7. Validation --------------------------------------------------------
//
// Catch config mistakes before they reach production.
// validateRoles: finds duplicate IDs, dangling inherits, cycles.
// validatePolicy: validates untrusted policy objects (e.g., from a DB).

console.log('\n--- Validation ---')
const rolesOk = access.validateRoles([viewer, editor, author, admin, orgEditor])
console.log('roles valid:', rolesOk.valid)

const policyOk = access.validatePolicy(publishPolicy)
console.log('policy valid:', policyOk.valid)

// Catch mistakes early
const badRoles = access.validateRoles([{ id: 'x', name: 'X', inherits: ['missing'], permissions: [] }])
console.log(
  'bad roles:',
  badRoles.issues.map((i) => i.message),
)

// -- 8. Engine setup ------------------------------------------------------
//
// The engine ties everything together: adapter + roles + cache.
// MemoryAdapter is great for dev/testing. Swap to PrismaAdapter or
// DrizzleAdapter for production, or HttpAdapter for a remote service.

const adapter = new MemoryAdapter({
  roles: [viewer, editor, author, admin, orgEditor],
  assignments: {
    alice: ['admin'],
    bob: ['author'],
    charlie: ['viewer'],
  },
  attributes: {
    bob: { department: 'engineering' },
  },
})

const engine = access.createEngine({
  adapter,
  cacheTTL: 60, // cache DB lookups for 60s
  hooks: {
    // Hooks observe decisions without modifying the engine.
    onDeny: (req, decision) => {
      console.log(`  [denied] ${req.subject.id} ${req.action} ${req.resource.type}`)
    },
  },
})

// -- 9. Permission checks -------------------------------------------------

async function main() {
  // Simple boolean check
  console.log('\n--- engine.can() ---')
  console.log('alice read post:', await engine.can('alice', 'read', { type: 'post', attributes: {} }))
  console.log('charlie create post:', await engine.can('charlie', 'create', { type: 'post', attributes: {} }))

  // Owner check -- bob can update his own post but not someone else's
  console.log('\n--- Owner conditions ---')
  console.log(
    'bob update own post:',
    await engine.can('bob', 'update', { type: 'post', id: 'p1', attributes: { ownerId: 'bob' } }),
  )
  console.log(
    "bob update alice's post:",
    await engine.can('bob', 'update', { type: 'post', id: 'p2', attributes: { ownerId: 'alice' } }),
  )

  // Detailed decision (includes reason, timing, matched rule/policy)
  console.log('\n--- engine.check() ---')
  const decision = await engine.check('charlie', 'delete', { type: 'post', attributes: {} })
  console.log('decision:', { allowed: decision.allowed, reason: decision.reason })

  // Batch check -- evaluate many permissions at once, returns a map.
  // This is what you send to the client so it can show/hide UI elements.
  console.log('\n--- engine.permissions() ---')
  const checks = access.checks([
    { action: 'read', resource: 'post' },
    { action: 'create', resource: 'post' },
    { action: 'delete', resource: 'post' },
    { action: 'update', resource: 'comment' },
  ])
  const bobPerms = await engine.permissions('bob', checks)
  console.log('bob permissions:', bobPerms)

  // -- 10. Debug with explain() -------------------------------------------
  //
  // When a permission is denied and you don't know why, explain() gives
  // a full trace: which policies matched, which rules fired, which
  // conditions passed/failed with actual vs expected values.
  console.log('\n--- engine.explain() ---')
  const explanation = await engine.explain('charlie', 'create', { type: 'post', attributes: {} })
  console.log(explanation.summary)

  // -- 11. Admin operations at runtime ------------------------------------
  //
  // Roles and policies can be modified at runtime through engine.admin.
  // Changes automatically invalidate the relevant caches.
  console.log('\n--- Runtime admin ---')
  await engine.admin.assignRole('charlie', 'editor')
  console.log('charlie create (promoted):', await engine.can('charlie', 'create', { type: 'post', attributes: {} }))

  await engine.admin.revokeRole('charlie', 'editor')
  engine.invalidate() // force full cache clear
  console.log('charlie create (demoted):', await engine.can('charlie', 'create', { type: 'post', attributes: {} }))

  // -- 12. Scoped role assignments ----------------------------------------
  //
  // Assign a role that only works within a specific scope (e.g., org).
  console.log('\n--- Scoped roles ---')
  await engine.admin.assignRole('charlie', 'editor', 'org-1')
  console.log(
    'charlie create in org-1:',
    await engine.can('charlie', 'create', { type: 'post', attributes: {} }, undefined, 'org-1'),
  )
  console.log(
    'charlie create in org-2:',
    await engine.can('charlie', 'create', { type: 'post', attributes: {} }, undefined, 'org-2'),
  )
  console.log('charlie create (no scope):', await engine.can('charlie', 'create', { type: 'post', attributes: {} }))
}

main().catch(console.error)
