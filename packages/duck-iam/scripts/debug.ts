#!/usr/bin/env node
/**
 * Compiled-engine debug playground for @gentleduck/iam.
 *
 * Not a test — nothing here asserts anything. It just wires up a small,
 * realistic role/policy graph and drives `IamEngine` (mode: 'production',
 * the compiled table) through the code paths that matter, with a
 * console.log before/after each call so you can see request -> decision.
 *
 * Drop your own `console.log(...)` anywhere in the engine while this runs:
 *   - maskFromRoles()        src/core/engine/compiled/compiled.lookup.ts
 *   - lookup()                src/core/engine/compiled/compiled.lookup.ts
 *   - rbacVote()               src/core/engine/compiled/compiled.lookup.ts
 *   - evaluateDynamicCell()    src/core/engine/compiled/compiled.lookup.ts
 *   - compileTable()           src/core/engine/compiled/compiled.compile.ts
 *   - _rebuildCompiledTable()  src/core/engine/engine.ts
 *
 * Usage: bun run debug   (or: bun run scripts/debug.ts)
 */

import { IamMemoryAdapter } from '../src/adapters/memory'
import { IamEngine } from '../src/core/engine/engine'
import type { AccessControl, IamPrimitives } from '../src/core/types'

// Literal unions instead of `AccessControl.IRole[]` / `IPolicy[]` (which pin
// TAction/TResource/TRole/TScope to their generic default of plain `string`,
// killing autocomplete before the engine ever sees the data). Naming these
// and threading them through `IRole<...>`/`IPolicy<...>` and
// `IamEngine<...>` below is what makes `.can()`/`.authorize()` autocomplete
// 'read' | 'update' | 'delete' | ... instead of accepting any string.
type TAction = 'read' | 'update' | 'delete' | 'admin:ban' | 'admin:*'
type TResource = 'post' | 'comment'
type TRole = 'viewer' | 'editor' | 'admin'
type TScope = 'org-1'

// ---------------------------------------------------------------------------
// 1. Roles — a 3-level inherits chain, so maskFromRoles/compileTable both
//    have something to fold. `admin`'s mask bit alone should be enough to
//    satisfy every permission below it in the chain.
// ---------------------------------------------------------------------------
const roles: AccessControl.IRole<TAction, TResource, TRole, TScope>[] = [
  { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
  {
    id: 'editor',
    name: 'Editor',
    inherits: ['viewer'],
    permissions: [{ action: 'update', resource: 'post', scope: 'org-1' }],
  },
  {
    id: 'admin',
    name: 'Admin',
    inherits: ['editor'],
    permissions: [{ action: 'delete', resource: 'post' }],
  },
]

// ---------------------------------------------------------------------------
// 2. Policies — one plain unconditional rule (CONST_ALLOW cell), one real
//    ABAC condition (DYNAMIC cell, hits evaluateDynamicCell), one wildcard
//    action (residual policy, skips the mask fast path entirely).
// ---------------------------------------------------------------------------
const policies: AccessControl.IPolicy<TAction, TResource, TRole>[] = [
  {
    id: 'allow-comment-read',
    name: 'Anyone can read comments',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'r1',
        effect: 'allow',
        priority: 0,
        actions: ['read'],
        resources: ['comment'],
        conditions: { all: [] },
      },
    ],
  },
  {
    id: 'allow-update-owned-post',
    name: 'Update your own post',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'r2',
        effect: 'allow',
        priority: 0,
        actions: ['update'],
        resources: ['post'],
        conditions: {
          all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }],
        },
      },
    ],
  },
  {
    id: 'wildcard-admin-actions',
    name: 'admin:* on anything, admins only',
    algorithm: 'allow-overrides',
    rules: [
      {
        id: 'r3',
        effect: 'allow',
        priority: 0,
        actions: ['admin:*'],
        resources: ['post'],
        conditions: { all: [{ field: 'subject.roles', operator: 'contains', value: 'admin' }] },
      },
    ],
  },
]

const assignments: Record<string, TRole[]> = {
  alice: ['viewer'],
  bob: ['editor'],
  carol: ['admin'],
}
const attributes: Record<string, IamPrimitives.Attributes> = {
  alice: {},
  bob: {},
  carol: {},
}

async function main() {
  // NOTE: policyCombine is 'allow-overrides', not 'and'. 'and' has an open bug
  // (see bottom of this file / ask the session about it): under 'and', ANY
  // policy without an explicit `target` whose *rules* don't match the current
  // action/resource still casts a real "deny" vote instead of abstaining —
  // only a policy-level `target` mismatch sets `applicable: false` and gets
  // skipped; a rule-level mismatch does not. Since 'and' is this engine's
  // default combine mode, that means one policy targeting an unrelated
  // resource silently vetoes every other policy's allow, in BOTH
  // mode: 'development' and mode: 'production'. Reproduced directly against
  // evaluate.ts, so it's not compiled-table-specific.
  const engine = new IamEngine<TAction, TResource, TRole, TScope, 'production'>({
    adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
    defaultEffect: 'deny',
    mode: 'production', // compiled table — the thing being debugged
    policyCombine: 'allow-overrides',
  })
  const devEngine = new IamEngine<TAction, TResource, TRole, TScope, 'development'>({
    adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
    defaultEffect: 'deny',
    mode: 'development', // explain() only works here — production throws
    policyCombine: 'allow-overrides',
  })

  const log = (label: string, result: unknown) => console.dir( result, { depth: null })
  // --- RBAC mask fast path: bob (editor -> inherits viewer) reading a post
  log(
    "bob can read 'post' (RBAC mask hit, via inherited viewer grant)",
    await engine.can('bob', 'read', { type: 'post', attributes: {} }),
  )

  // // --- RBAC mask miss, falls through to residual/DYNAMIC policy
  // log(
  //   "alice (viewer only) can update her own 'post' (DYNAMIC cell, ownership condition true)",
  //   await engine.can('bob', 'update', { type: 'post', attributes: { ownerId: 'bob' } }),
  // )
  // log(
  //   "bob can update SOMEONE ELSE's 'post' (DYNAMIC cell, ownership condition false)",
  //   await engine.can('bob', 'update', { type: 'post', attributes: { ownerId: 'not-bob' } }),
  // )

  // // --- Wildcard residual policy: never in the mask, always falls to policy eval
  // log(
  //   "carol (admin) can 'admin:ban' a post (residual wildcard policy)",
  //   await engine.can('carol', 'admin:ban', { type: 'post', attributes: {} }),
  // )
  // log(
  //   "alice (viewer, not admin) can 'admin:ban' a post (condition false -> deny)",
  //   await engine.can('alice', 'admin:ban', { type: 'post', attributes: {} }),
  // )

  // // --- Full decision trace (explain runs the interpreter path, useful to
  // //     compare against what the compiled table decided above). Note
  // //     explain() takes a subjectId, not a request object, unlike authorize().
  // const explanation = await devEngine.explain('bob', 'update', {
  //   type: 'post',
  //   attributes: { ownerId: 'bob' },
  // })
  // log('explain(): bob updating his own post', explanation)

  // // --- permissions(): the other public entry point that reads the compiled table
  // log(
  //   "permissions(): batch-checking carol (admin) on 'post'",
  //   await engine.permissions('carol', [
  //     { action: 'read', resource: 'post' },
  //     { action: 'update', resource: 'post' },
  //     { action: 'delete', resource: 'post' },
  //     { action: 'admin:ban', resource: 'post' },
  //   ]),
  // )

  // // --- Invalidation -> forces _rebuildCompiledTable() on the next call
  // console.log('\n[invalidating roles + rebuilding compiled table...]')
  // engine.cache.invalidateRoles()
  // log(
  //   "carol can delete a 'post' after invalidation (table rebuilt on demand)",
  //   await engine.can('carol', 'delete', { type: 'post', attributes: {} }),
  // )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
