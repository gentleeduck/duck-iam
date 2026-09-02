import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../../shared/keys'
import { REGEX_CACHE_MAX } from '../../../conditions/conditions.libs'
import type { AccessControl, IamPrimitives, IamRequest } from '../../../types'
import { IamEngine } from '../../engine'
import { compileTable } from '../compiled.compile'
import { lookup } from '../compiled.lookup'

// Boundary + error-handling-path coverage for the compiled table, additive to
// compiled.engine-wiring.test.ts / compiled.compile.test.ts / compiled.differential.test.ts.
// Does NOT re-test what those files already cover (mixed simple+residual RBAC on one
// role, >32 roles failing closed, invalidation rebuilding the table, the stale
// in-flight-table race, the RBAC-residual-abstain regression) - see each section below
// for exactly what is new.

function req(
  subjectRoles: string[],
  action: string,
  resource: string,
  attributes: IamPrimitives.Attributes = {},
): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: subjectRoles, attributes: {} },
    action,
    resource: { type: resource, attributes },
    environment: { now: 1 },
  }
}

/** Long enough to trip MAX_REGEX_INPUT_LENGTH (2048) and make the `matches` operator throw. */
const OVERSIZED = 'a'.repeat(4096)

// ---------------------------------------------------------------------------------------
// 1. Boundary role counts
// ---------------------------------------------------------------------------------------

describe('boundary: 0 roles - no RBAC source at all', () => {
  it('hasRbacSource is false for an empty role list (compileTable)', () => {
    const t = compileTable([], [], 'and')
    expect(t.hasRbacSource).toBe(false)
  })

  it('RBAC casts no vote at all (not even a defaultEffect vote) - distinct from voting defaultEffect', () => {
    // ABAC votes a real, unconditional `true` (CONST_ALLOW) at this exact cell. If RBAC
    // wrongly cast its own defaultEffect=false vote instead of abstaining (hasRbacSource
    // false), 'and' would flip this to false despite the ABAC allow.
    const policies: AccessControl.IPolicy[] = [
      {
        id: 'p',
        name: 'p',
        algorithm: 'allow-overrides',
        rules: [
          { id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc'], conditions: { all: [] } },
        ],
      },
    ]
    const t = compileTable([], policies, 'and')
    expect(t.hasRbacSource).toBe(false)
    const request = req([], 'read', 'doc')
    expect(lookup(t, 0, 'read', 'doc', request, 'deny')).toBe(true)
  })
})

describe('boundary: exactly 1 role', () => {
  it('the sole role holder is granted, a non-holder of any role is denied', async () => {
    const roles: AccessControl.IRole[] = [
      { id: 'only-role', name: 'Only Role', permissions: [{ action: 'read', resource: 'doc' }] },
    ]
    const adapter = new IamMemoryAdapter({
      roles,
      policies: [],
      assignments: { holder: ['only-role'], stranger: [] },
      attributes: { holder: {}, stranger: {} },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    const resource = { type: 'doc', attributes: {} }
    expect(await production.can('holder', 'read', resource)).toBe(true)
    expect(await production.can('stranger', 'read', resource)).toBe(false)
  })
})

describe('boundary: exactly 32 roles - role index 31 (the sign-bit case, `1 << 31` is negative in JS)', () => {
  it("role 31's grant round-trips true for its sole holder, and false for a subject holding every other role", async () => {
    const roles: AccessControl.IRole[] = Array.from({ length: 32 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: i === 31 ? [{ action: 'read', resource: 'secret31' }] : [],
    }))
    const allButLast = roles.slice(0, 31).map((r) => r.id)
    const adapter = new IamMemoryAdapter({
      roles,
      policies: [],
      assignments: { holder31: ['role-31'], holder0to30: allButLast },
      attributes: { holder31: {}, holder0to30: {} },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    const resource = { type: 'secret31', attributes: {} }
    expect(await production.can('holder31', 'read', resource)).toBe(true)
    expect(await production.can('holder0to30', 'read', resource)).toBe(false)
  })
})

// ---------------------------------------------------------------------------------------
// 2. The full fail-skip / abstain matrix.
//
// Four independent abstain paths, each must return `null` (abstain) - not vote - when a
// policy throws:
//   A: abacFlatVote's evaluateDynamicCell, when every group at a DYNAMIC cell throws.
//   B: rbacVote's catch, when the rbacResidual policy throws.
//   C: lookup()'s own residual-policy loop, when a residual (targeted/wildcard) policy throws.
//   D: rbacVote's rbacDynamic scan, when a scoped/conditioned role permission throws.
//
// For each: an "unrelated vote present" case (must decide the outcome, not get vetoed by
// the throw, under policyCombine 'and') and a "no other vote" case (falls back to
// defaultEffect, both 'allow' and 'deny'). compiled.engine-wiring.test.ts already covers
// path B's unrelated-vote-present case with defaultEffect 'deny' and the unrelated vote
// coming from a flat ABAC CONST_ALLOW policy - not duplicated here; the path-B
// unrelated-vote-present test below uses a *residual* (targeted) policy as the unrelated
// vote instead, exercising a different combine branch (lookup()'s residualPolicies loop)
// alongside the same rbacVote throw.
// ---------------------------------------------------------------------------------------

const throwingFlatPolicy: AccessControl.IPolicy = {
  id: 'throwing-flat',
  name: 'Throwing Flat',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r',
      effect: 'allow',
      priority: 0,
      actions: ['read'],
      resources: ['doc'],
      conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+$' }] },
    },
  ],
}

function buildPathAAdapter(): IamMemoryAdapter {
  const roles: AccessControl.IRole[] = [
    { id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'doc' }] },
  ]
  return new IamMemoryAdapter({
    roles,
    policies: [throwingFlatPolicy],
    assignments: { 'user-1': ['reader'] },
    attributes: { 'user-1': { blob: OVERSIZED } },
  })
}

describe('fail-skip matrix - path A: every group at an ABAC DYNAMIC cell throws (evaluateDynamicCell)', () => {
  it("unrelated-vote-present, defaultEffect 'deny': the RBAC grant decides, the throw does not veto it (regression)", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathAAdapter(),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathAAdapter(), defaultEffect: 'deny' })
    const resource = { type: 'doc', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toMatch(/MAX_REGEX_INPUT_LENGTH/)
  })

  it("unrelated-vote-present, defaultEffect 'allow': still decided by the RBAC grant, not the fallback", async () => {
    const production = new IamEngine({
      adapter: buildPathAAdapter(),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({ adapter: buildPathAAdapter(), defaultEffect: 'allow', allowFailOpen: true })
    const resource = { type: 'doc', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })

  it("no-other-vote, defaultEffect 'deny': falls back to deny (no RBAC source, no residual policies)", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [],
      policies: [throwingFlatPolicy],
      assignments: {},
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc', attributes: {} })).toBe(false)
  })

  it("no-other-vote, defaultEffect 'allow': falls back to allow", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [],
      policies: [throwingFlatPolicy],
      assignments: {},
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'allow', allowFailOpen: true, mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc', attributes: {} })).toBe(true)
  })
})

const complexThrowingRole: AccessControl.IRole = {
  id: 'complex-role',
  name: 'Complex Role',
  permissions: [
    {
      action: 'read',
      resource: 'doc2',
      conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+$' }] },
    },
  ],
}

const unrelatedResidualAllow: AccessControl.IPolicy = {
  id: 'unrelated-residual-allow',
  name: 'Unrelated Residual Allow',
  algorithm: 'allow-overrides',
  targets: { actions: ['read'] },
  rules: [{ id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc2'], conditions: { all: [] } }],
}

const unrelatedFlatAllow: AccessControl.IPolicy = {
  id: 'unrelated-flat-allow',
  name: 'Unrelated Flat Allow',
  algorithm: 'allow-overrides',
  rules: [{ id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc2'], conditions: { all: [] } }],
}

function buildPathBAdapter(unrelated: AccessControl.IPolicy): IamMemoryAdapter {
  return new IamMemoryAdapter({
    roles: [complexThrowingRole],
    policies: [unrelated],
    assignments: { 'user-1': ['complex-role'] },
    attributes: { 'user-1': { blob: OVERSIZED } },
  })
}

describe('fail-skip matrix - path B: the rbacResidual policy throws (rbacVote catch)', () => {
  it("unrelated-vote-present, defaultEffect 'deny', unrelated vote via a residual policy: decides, not vetoed", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathBAdapter(unrelatedResidualAllow),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathBAdapter(unrelatedResidualAllow), defaultEffect: 'deny' })
    const resource = { type: 'doc2', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toMatch(/MAX_REGEX_INPUT_LENGTH/)
  })

  it("unrelated-vote-present, defaultEffect 'allow', unrelated vote via a flat CONST_ALLOW policy", async () => {
    const production = new IamEngine({
      adapter: buildPathBAdapter(unrelatedFlatAllow),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({
      adapter: buildPathBAdapter(unrelatedFlatAllow),
      defaultEffect: 'allow',
      allowFailOpen: true,
    })
    const resource = { type: 'doc2', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })

  it("no-other-vote, defaultEffect 'deny': falls back to deny (no ABAC policies at all)", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [complexThrowingRole],
      policies: [],
      assignments: { 'user-1': ['complex-role'] },
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc2', attributes: {} })).toBe(false)
  })

  it("no-other-vote, defaultEffect 'allow': falls back to allow", async () => {
    const adapter = new IamMemoryAdapter({
      roles: [complexThrowingRole],
      policies: [],
      assignments: { 'user-1': ['complex-role'] },
      attributes: { 'user-1': { blob: OVERSIZED } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'allow', allowFailOpen: true, mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc2', attributes: {} })).toBe(true)
  })
})

const throwingResidualPolicy: AccessControl.IPolicy = {
  id: 'throwing-residual',
  name: 'Throwing Residual',
  algorithm: 'deny-overrides',
  targets: { actions: ['read'] },
  rules: [
    {
      id: 'r',
      effect: 'deny',
      priority: 0,
      actions: ['read'],
      resources: ['doc3'],
      conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+$' }] },
    },
  ],
}

function buildPathCAdapter(withRbac: boolean): IamMemoryAdapter {
  const roles: AccessControl.IRole[] = withRbac
    ? [{ id: 'reader3', name: 'Reader3', permissions: [{ action: 'read', resource: 'doc3' }] }]
    : []
  return new IamMemoryAdapter({
    roles,
    policies: [throwingResidualPolicy],
    assignments: withRbac ? { 'user-1': ['reader3'] } : {},
    attributes: { 'user-1': { blob: OVERSIZED } },
  })
}

describe("fail-skip matrix - path C: lookup()'s own residual-policy loop throws", () => {
  it("unrelated-vote-present, defaultEffect 'deny': the RBAC grant decides, the residual throw does not veto it", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathCAdapter(true),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathCAdapter(true), defaultEffect: 'deny' })
    const resource = { type: 'doc3', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toMatch(/MAX_REGEX_INPUT_LENGTH/)
  })

  it("unrelated-vote-present, defaultEffect 'allow'", async () => {
    const production = new IamEngine({
      adapter: buildPathCAdapter(true),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    const development = new IamEngine({ adapter: buildPathCAdapter(true), defaultEffect: 'allow', allowFailOpen: true })
    const resource = { type: 'doc3', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })

  it("no-other-vote, defaultEffect 'deny': falls back to deny (no RBAC, no flat ABAC policies)", async () => {
    const production = new IamEngine({ adapter: buildPathCAdapter(false), defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc3', attributes: {} })).toBe(false)
  })

  it("no-other-vote, defaultEffect 'allow': falls back to allow", async () => {
    const production = new IamEngine({
      adapter: buildPathCAdapter(false),
      defaultEffect: 'allow',
      allowFailOpen: true,
      mode: 'production',
    })
    expect(await production.can('user-1', 'read', { type: 'doc3', attributes: {} })).toBe(true)
  })
})

// Path D's throwing source is a role permission, not a policy: literal action+resource plus
// a condition puts it in `rbacDynamic`, and a throw there poisons the whole cell scan
// (all-or-nothing, unlike ABAC's per-group fail-skip) - so rbacVote must abstain outright.
function buildPathDAdapter(withAbac: boolean): IamMemoryAdapter {
  const roles: AccessControl.IRole[] = [
    {
      id: 'reader4',
      name: 'Reader4',
      permissions: [
        {
          action: 'read',
          resource: 'doc4',
          conditions: { all: [{ field: 'subject.attributes.blob', operator: 'matches', value: '^a+$' }] },
        },
      ],
    },
  ]
  const unrelatedAllow: AccessControl.IPolicy = {
    id: 'unrelated-allow',
    name: 'Unrelated Allow',
    algorithm: 'allow-overrides',
    rules: [{ id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['doc4'], conditions: { all: [] } }],
  }
  return new IamMemoryAdapter({
    roles,
    policies: withAbac ? [unrelatedAllow] : [],
    assignments: { 'user-1': ['reader4'] },
    attributes: { 'user-1': { blob: OVERSIZED } },
  })
}

describe("fail-skip matrix - path D: rbacVote's rbacDynamic scan throws", () => {
  it("unrelated-vote-present, defaultEffect 'deny': the ABAC allow decides, the throw does not veto it", async () => {
    let reported: Error | undefined
    const production = new IamEngine({
      adapter: buildPathDAdapter(true),
      defaultEffect: 'deny',
      mode: 'production',
      hooks: { onPolicyError: (err) => (reported = err) },
    })
    const development = new IamEngine({ adapter: buildPathDAdapter(true), defaultEffect: 'deny' })
    const resource = { type: 'doc4', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
    expect(reported?.message).toMatch(/MAX_REGEX_INPUT_LENGTH/)
  })

  it("no-other-vote, defaultEffect 'deny': falls back to deny", async () => {
    const production = new IamEngine({ adapter: buildPathDAdapter(false), defaultEffect: 'deny', mode: 'production' })
    expect(await production.can('user-1', 'read', { type: 'doc4', attributes: {} })).toBe(false)
  })

  it("no-other-vote, defaultEffect 'allow': falls back to allow", async () => {
    const production = new IamEngine({
      adapter: buildPathDAdapter(false),
      allowFailOpen: true,
      defaultEffect: 'allow',
      mode: 'production',
    })
    expect(await production.can('user-1', 'read', { type: 'doc4', attributes: {} })).toBe(true)
  })
})

// ---------------------------------------------------------------------------------------
// 3. Cache isolation between two engine instances.
//
// stats.get() only exposes the policy/role/rbacPolicy/mergedPolicy/subject caches, not the
// per-instance regex/path caches `IamEngine` threads through `lookup()`/`evaluate()` (see
// `_caches` and `iamFlushSharedCaches()`'s doc in engine.ts). There is no public accessor
// for them, so this reaches the private field via a runtime type guard (no `as` cast) - the
// guard fails loudly if the internal shape ever changes, instead of silently no-op'ing.
// ---------------------------------------------------------------------------------------

interface IEngineInternalCaches {
  regex: Map<string, RegExp>
  path: Map<string, string[] | null>
}

function hasInternalCaches(v: unknown): v is { _caches: IEngineInternalCaches } {
  if (typeof v !== 'object' || v === null || !('_caches' in v)) return false
  const caches = v._caches
  if (typeof caches !== 'object' || caches === null) return false
  if (!('regex' in caches) || !('path' in caches)) return false
  return caches.regex instanceof Map && caches.path instanceof Map
}

function internalCachesOf(engine: unknown): IEngineInternalCaches {
  if (!hasInternalCaches(engine)) {
    throw new Error('IamEngine internal `_caches` shape not found - update this test helper if engine.ts changed.')
  }
  return engine._caches
}

function matchesPolicy(id: string, patternField: string): AccessControl.IPolicy {
  return {
    id,
    name: id,
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'r',
        effect: 'allow',
        priority: 0,
        actions: ['read'],
        resources: ['doc'],
        conditions: { all: [{ field: 'subject.attributes.x', operator: 'matches', value: patternField }] },
      },
    ],
  }
}

/** One policy with N rules, each a distinct `matches` pattern at the same cell - `evaluateDynamicCell` evaluates every rule's condition unconditionally (no short-circuit), so one `can()` call compiles all N patterns. */
function manyPatternsPolicy(id: string, count: number): AccessControl.IPolicy {
  return {
    id,
    name: id,
    algorithm: 'deny-overrides',
    rules: Array.from({ length: count }, (_, i) => ({
      id: `r${i}`,
      effect: 'allow' as const,
      priority: 0,
      actions: ['read'],
      resources: ['doc'],
      conditions: { all: [{ field: 'subject.attributes.x', operator: 'matches' as const, value: `^pattern-${i}$` }] },
    })),
  }
}

describe('cache isolation between two IamEngine instances (multi-tenant safety)', () => {
  it('two engines never share the same regex/path cache Map instances, and filling one does not affect the other', async () => {
    const engineA = new IamEngine({
      adapter: new IamMemoryAdapter({
        roles: [],
        policies: [manyPatternsPolicy('warm-a', 500)],
        assignments: {},
        attributes: { u: { x: 'no-match' } },
      }),
      defaultEffect: 'deny',
      mode: 'production',
    })
    const engineB = new IamEngine({
      adapter: new IamMemoryAdapter({
        roles: [],
        policies: [matchesPolicy('b-policy', '^only-b$')],
        assignments: {},
        attributes: { u: { x: 'no-match' } },
      }),
      defaultEffect: 'deny',
      mode: 'production',
    })

    const cachesA = internalCachesOf(engineA)
    const cachesB = internalCachesOf(engineB)
    // Structural isolation: distinct Map objects per instance.
    expect(cachesA.regex).not.toBe(cachesB.regex)
    expect(cachesA.path).not.toBe(cachesB.path)
    expect(cachesA.regex.size).toBe(0)
    expect(cachesB.regex.size).toBe(0)

    // Warm engine A with far more distinct regex patterns than a shared REGEX_CACHE_MAX
    // (256) cache would tolerate without evicting the other tenant's entries.
    await engineA.can('u', 'read', { type: 'doc', attributes: {} })
    expect(cachesA.regex.size).toBe(REGEX_CACHE_MAX)
    // Engine B's own cache must be completely untouched by A's warmup.
    expect(cachesB.regex.size).toBe(0)

    // Engine B evaluates its own single pattern - correct regardless of A's warmup, and
    // only affects B's own cache.
    expect(await engineB.can('u', 'read', { type: 'doc', attributes: {} })).toBe(false) // 'no-match' doesn't match '^only-b$'
    expect(cachesB.regex.size).toBe(1)
    expect(cachesA.regex.size).toBe(REGEX_CACHE_MAX) // unaffected by B's operation
  })
})

// ---------------------------------------------------------------------------------------
// 4. Concurrent-invalidation stress: MULTIPLE overlapping invalidations racing several
// concurrent authorize() calls against a gated adapter, beyond compiled.engine-wiring.test.ts's
// single-race regression. Intermediate racing calls' exact values are not asserted (that's
// inherently racy); only that the engine settles to a state consistent with a fresh oracle
// development engine reading the final adapter data.
// ---------------------------------------------------------------------------------------

describe('production mode: multiple overlapping invalidations settle to a state consistent with a fresh oracle', () => {
  it('several concurrent authorize() calls plus back-to-back invalidateRoles/invalidatePolicies/invalidateAll never leave a corrupted table', async () => {
    let releaseGate!: () => void
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve
    })
    const initialRoles: AccessControl.IRole[] = [
      { id: 'editor', name: 'Editor', permissions: [{ action: 'update', resource: 'post' }] },
    ]
    const inner = new IamMemoryAdapter({
      roles: initialRoles,
      policies: [],
      assignments: { 'user-1': ['editor'] },
      attributes: { 'user-1': {} },
    })
    const gatedAdapter = new Proxy(inner, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver)
        if (prop === 'listPolicies' && typeof value === 'function') {
          return async (...args: unknown[]) => {
            await gate
            return (value as (...a: unknown[]) => unknown).apply(target, args)
          }
        }
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const engine = new IamEngine({ adapter: gatedAdapter, defaultEffect: 'deny', mode: 'production' })
    const subject = { id: 'user-1', roles: ['editor'], attributes: {} }
    const resource = { type: 'post', attributes: {} }

    // Wave 1: several concurrent calls, all starting (and blocking on the gate) before any
    // mutation lands.
    const wave1 = [
      engine.authorize({ subject, action: 'update', resource }),
      engine.authorize({ subject, action: 'update', resource }),
      engine.authorize({ subject, action: 'update', resource }),
    ]

    // Overlapping invalidations, all landing strictly before the gate is released, each
    // bumping the generation and nulling the compiled table. Only the role revocation
    // actually changes the decision (deliberately: this keeps `expected` unambiguous - a
    // stale in-flight table built from the pre-revocation role snapshot would still
    // evaluate to `true`, diverging from the correct post-revocation `false`), the other
    // two invalidation calls are no-op data-wise but must still not corrupt anything.
    await inner.saveRole({ id: 'editor', name: 'Editor', permissions: [] }) // revoke the grant
    engine.cache.invalidateRoles('editor')
    engine.cache.invalidatePolicies()
    engine.cache.invalidate()

    // Wave 2: more concurrent calls, starting strictly after all three invalidations, still
    // gated (the adapter hasn't released listPolicies yet). Unlike wave 1 (which raced the
    // invalidations and may have started before any of them landed), every wave-2 call
    // starts under the post-invalidation generation and so - per the single-flight
    // contract - must never be handed a stale pre-revocation table: assert these directly,
    // not just the eventually-settled state below.
    const wave2 = [
      engine.authorize({ subject, action: 'update', resource }),
      engine.authorize({ subject, action: 'update', resource }),
    ]

    releaseGate()
    // Wave 1 raced the invalidations and may have started before any landed - its
    // individual results are inherently racy and not asserted either way.
    await Promise.all(wave1)
    const oracle = new IamEngine({ adapter: inner, defaultEffect: 'deny' })
    const expected = (await oracle.check('user-1', 'update', resource)).allowed
    expect(expected).toBe(false) // sanity: role revoked, so the grant is gone
    for (const result of await Promise.all(wave2)) {
      expect(result).toBe(expected)
    }

    // Settled: a fresh oracle development engine reading the SAME final adapter state is
    // ground truth. Every post-settlement call must agree with it, repeatedly.
    for (let i = 0; i < 5; i++) {
      expect(await engine.authorize({ subject, action: 'update', resource })).toBe(expected)
    }
  })
})

// ---------------------------------------------------------------------------------------
// 5. permissions() batch-check parity, for one fail-skip case and the 32-role boundary case.
// ---------------------------------------------------------------------------------------

describe('permissions() batch-check parity', () => {
  it('agrees with can() for the path-A abstain-vs-unrelated-RBAC-vote case', async () => {
    const production = new IamEngine({ adapter: buildPathAAdapter(), defaultEffect: 'deny', mode: 'production' })
    const checks = [{ action: 'read', resource: 'doc' }] as const
    const map = await production.permissions('user-1', checks)
    const key = iamBuildPermissionKey('read', 'doc')
    expect(map[key]).toBe(true)
    expect(map[key]).toBe(await production.can('user-1', 'read', { type: 'doc', attributes: {} }))
  })

  it('agrees with can() for the 32-role sign-bit boundary case (both the holder and the non-holder)', async () => {
    const roles: AccessControl.IRole[] = Array.from({ length: 32 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: i === 31 ? [{ action: 'read', resource: 'secret31' }] : [],
    }))
    const allButLast = roles.slice(0, 31).map((r) => r.id)
    const adapter = new IamMemoryAdapter({
      roles,
      policies: [],
      assignments: { holder31: ['role-31'], holder0to30: allButLast },
      attributes: { holder31: {}, holder0to30: {} },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    const checks = [{ action: 'read', resource: 'secret31' }] as const
    const key = iamBuildPermissionKey('read', 'secret31')

    const mapHolder = await production.permissions('holder31', checks)
    const mapOther = await production.permissions('holder0to30', checks)
    expect(mapHolder[key]).toBe(true)
    expect(mapOther[key]).toBe(false)
    expect(mapHolder[key]).toBe(await production.can('holder31', 'read', { type: 'secret31', attributes: {} }))
    expect(mapOther[key]).toBe(await production.can('holder0to30', 'read', { type: 'secret31', attributes: {} }))
  })
})
