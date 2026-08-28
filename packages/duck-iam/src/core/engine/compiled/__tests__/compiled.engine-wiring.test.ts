import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../../shared/keys'
import { IamEngine } from '../../engine'

// mode: 'production' now always uses the compiled table - no opt-in flag, no
// fallthrough. These tests compare a production engine's boolean verdicts
// against a development engine (the interpreted ground truth) over the same
// data, for both policyCombine modes, plus the invalidation contract.

const roles = [{ id: 'editor', name: 'Editor', permissions: [{ action: 'update', resource: 'post' }] }]
const policies = [
  {
    id: 'ownership',
    name: 'Ownership',
    algorithm: 'deny-overrides' as const,
    rules: [
      {
        id: 'r',
        effect: 'allow' as const,
        priority: 0,
        actions: ['read'],
        resources: ['post'],
        conditions: {
          all: [{ field: 'subject.id', operator: 'eq' as const, value: '$resource.attributes.ownerId' }],
        },
      },
    ],
  },
]
const assignments = { 'user-1': ['editor'] }
const attributes = { 'user-1': {} }

describe.each(['and', 'allow-overrides'] as const)('production mode (policyCombine: %s)', (policyCombine) => {
  it('ROLE_MASK-covered request: production and development engines agree', async () => {
    const production = new IamEngine({
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      mode: 'production',
      policyCombine,
    })
    const development = new IamEngine({
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      policyCombine,
    })
    const resource = { type: 'post', attributes: {} }
    expect(await production.can('user-1', 'update', resource)).toBe(
      (await development.check('user-1', 'update', resource)).allowed,
    )
  })

  it('DYNAMIC-covered request: production and development engines agree', async () => {
    const production = new IamEngine({
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      mode: 'production',
      policyCombine,
    })
    const development = new IamEngine({
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      policyCombine,
    })
    const owned = { type: 'post', attributes: { ownerId: 'user-1' } }
    const notOwned = { type: 'post', attributes: { ownerId: 'someone-else' } }
    expect(await production.can('user-1', 'read', owned)).toBe(
      (await development.check('user-1', 'read', owned)).allowed,
    )
    expect(await production.can('user-1', 'read', notOwned)).toBe(
      (await development.check('user-1', 'read', notOwned)).allowed,
    )
  })

  it('permissions() batch check agrees with development for the same requests', async () => {
    const production = new IamEngine({
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      mode: 'production',
      policyCombine,
    })
    const development = new IamEngine({
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      policyCombine,
    })
    const checks = [
      { action: 'update', resource: 'post' },
      { action: 'read', resource: 'post', resourceId: 'p1' },
    ] as const
    const prodMap = await production.permissions('user-1', checks)
    for (const c of checks) {
      const decision = await development.check('user-1', c.action, {
        type: c.resource,
        id: 'resourceId' in c ? c.resourceId : undefined,
        attributes: {},
      })
      const key = iamBuildPermissionKey(c.action, c.resource, 'resourceId' in c ? c.resourceId : undefined)
      expect(prodMap[key]).toBe(decision.allowed)
    }
  })
})

describe("production mode: 'and'-mode soundness (the bug this design exists to fix)", () => {
  it('an irrelevant second untargeted policy correctly vetoes an otherwise-granted role permission', async () => {
    const irrelevant = {
      id: 'irrelevant',
      name: 'Irrelevant',
      algorithm: 'deny-overrides' as const,
      rules: [
        {
          id: 'r',
          effect: 'allow' as const,
          priority: 0,
          actions: ['nothing-to-do-with-this'],
          resources: ['other'],
          conditions: { all: [] },
        },
      ],
    }
    const adapter = new IamMemoryAdapter({
      roles,
      policies: [...policies, irrelevant],
      assignments,
      attributes,
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' }) // policyCombine: 'and' default
    // Under 'and', `irrelevant` is applicable (untargeted) but has zero rules
    // at update/post, so it votes defaultEffect=false - must veto the role grant.
    expect(await production.can('user-1', 'update', { type: 'post', attributes: {} })).toBe(false)
  })
})

describe('production mode: mixed simple+residual RBAC on one role (regression)', () => {
  it("a scoped permission elsewhere on the same role does not veto the role's plain grant under 'and'", async () => {
    const mixedRoles = [
      {
        id: 'editor',
        name: 'Editor',
        permissions: [
          { action: 'read', resource: 'post' }, // simple
          { action: 'update', resource: 'post', scope: 'org-1' }, // residual, unrelated cell
        ],
      },
    ]
    const adapter = new IamMemoryAdapter({
      roles: mixedRoles,
      policies: [],
      assignments: { 'user-1': ['editor'] },
      attributes: { 'user-1': {} },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' }) // 'and' default
    const development = new IamEngine({
      adapter: new IamMemoryAdapter({
        roles: mixedRoles,
        policies: [],
        assignments: { 'user-1': ['editor'] },
        attributes: { 'user-1': {} },
      }),
      defaultEffect: 'deny',
    })
    const resource = { type: 'post', attributes: {} }
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })
})

describe('production mode: role count beyond the 32-bit mask capacity', () => {
  it('fails closed (deny) instead of aliasing role bits, and reports via onError', async () => {
    const tooManyRoles = Array.from({ length: 33 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: i === 0 ? [{ action: 'delete', resource: 'secret' }] : [],
    }))
    const adapter = new IamMemoryAdapter({
      roles: tooManyRoles,
      policies: [],
      assignments: { guest: ['role-32'] }, // aliases role-0's bit under the old (buggy) `1 << 32` behavior
      attributes: { guest: {} },
    })
    let reportedError: Error | undefined
    const production = new IamEngine({
      adapter,
      defaultEffect: 'deny',
      mode: 'production',
      hooks: {
        onError: (err) => {
          reportedError = err
        },
      },
    })
    const allowed = await production.can('guest', 'delete', { type: 'secret', attributes: {} })
    expect(allowed).toBe(false)
    expect(reportedError?.message).toMatch(/32/)
  })
})

describe('production mode: invalidation rebuilds the compiled table', () => {
  it('a role invalidation drops a stale ROLE_MASK grant', async () => {
    const adapter = new IamMemoryAdapter({ roles, policies, assignments, attributes })
    const engine = new IamEngine({
      adapter,
      defaultEffect: 'deny',
      mode: 'production',
      policyCombine: 'allow-overrides',
    })
    const resource = { type: 'post', attributes: {} }
    expect(await engine.can('user-1', 'update', resource)).toBe(true)
    await adapter.saveRole({ id: 'editor', name: 'Editor', permissions: [] }) // revoke the permission
    engine.cache.invalidateRoles('editor')
    expect(await engine.can('user-1', 'update', resource)).toBe(false)
  })

  it('a policy invalidation is reflected on the next check', async () => {
    const adapter = new IamMemoryAdapter({ roles: [], policies, assignments: {}, attributes: {} })
    const engine = new IamEngine({
      adapter,
      defaultEffect: 'deny',
      mode: 'production',
      policyCombine: 'allow-overrides',
    })
    const owned = { type: 'post', attributes: { ownerId: 'user-1' } }
    expect(await engine.can('user-1', 'read', owned)).toBe(true)
    await adapter.deletePolicy('ownership')
    engine.cache.invalidatePolicies()
    expect(await engine.can('user-1', 'read', owned)).toBe(false)
  })

  it('a caller arriving after an invalidation that lands mid-rebuild never gets the stale in-flight table (regression)', async () => {
    // Gate the adapter's listPolicies so a compiled-table rebuild started by the first
    // `can()` call stays in flight until we explicitly release it - long enough to land
    // a role revocation + invalidation while that rebuild is still pending.
    let releaseGate!: () => void
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve
    })
    const inner = new IamMemoryAdapter({ roles, policies: [], assignments, attributes })
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
    const resource = { type: 'post', attributes: {} }
    // A full subject object (not a subjectId) so `authorize()` skips `_resolveSubject`'s
    // own adapter round-trip - the compiled-table rebuild starts synchronously on the
    // call, so `listRoles` snapshots deterministically before any test code resumes.
    const subject = { id: 'user-1', roles: ['editor'], attributes: {} }

    // R1: starts the rebuild; blocks on the gated listPolicies call. `listRoles` (no
    // gate) resolves and snapshots the pre-revocation role data synchronously, within
    // this same call, before the `await` below ever yields control.
    const r1 = engine.authorize({ subject, action: 'update', resource })

    // Revoke the permission and invalidate strictly BEFORE R1's rebuild has resolved.
    await inner.saveRole({ id: 'editor', name: 'Editor', permissions: [] })
    engine.cache.invalidateRoles('editor')

    // R2: starts strictly AFTER the invalidation, while R1's rebuild is still pending.
    // Must not be handed R1's in-flight promise (which resolves from the stale,
    // pre-revocation role snapshot) - it must observe the revocation.
    const r2 = engine.authorize({ subject, action: 'update', resource })

    releaseGate()
    expect(await r2).toBe(false)
    // R1 raced the invalidation and started before it landed - its result is not
    // asserted either way, but it must not corrupt the engine's cached table for
    // subsequent callers (checked by R3 below).
    await r1

    // R3: after everything has settled, the table must reflect the revocation.
    expect(await engine.authorize({ subject, action: 'update', resource })).toBe(false)
  })
})

describe('production mode: rotten RBAC residual policy abstains instead of fail-closed vetoing (regression)', () => {
  it("an oversized subject attribute that makes the residual policy's condition throw does not veto an unrelated ABAC allow under 'and'", async () => {
    const conditionalRoles = [
      {
        id: 'editor',
        name: 'Editor',
        permissions: [
          {
            action: 'read',
            resource: 'post',
            conditions: {
              all: [{ field: 'subject.attributes.blob', operator: 'matches' as const, value: '^a+$' }],
            },
          },
        ],
      },
    ]
    const abacPolicies = [
      {
        id: 'abac-allow',
        name: 'ABAC allow',
        algorithm: 'deny-overrides' as const,
        rules: [
          {
            id: 'r',
            effect: 'allow' as const,
            priority: 0,
            actions: ['read'],
            resources: ['post'],
            conditions: { all: [] },
          },
        ],
      },
    ]
    // Long enough to trip the regex-matching engine's input-length guard and throw.
    const oversizedBlob = 'a'.repeat(4096)
    const adapter = new IamMemoryAdapter({
      roles: conditionalRoles,
      policies: abacPolicies,
      assignments: { 'user-1': ['editor'] },
      attributes: { 'user-1': { blob: oversizedBlob } },
    })
    const production = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' }) // 'and' default
    const development = new IamEngine({
      adapter: new IamMemoryAdapter({
        roles: conditionalRoles,
        policies: abacPolicies,
        assignments: { 'user-1': ['editor'] },
        attributes: { 'user-1': { blob: oversizedBlob } },
      }),
      defaultEffect: 'deny',
    })
    const resource = { type: 'post', attributes: {} }
    // The rotten RBAC residual policy must abstain (not vote deny), so the unrelated
    // ABAC allow still carries the request under 'and'.
    expect(await production.can('user-1', 'read', resource)).toBe(true)
    expect(await production.can('user-1', 'read', resource)).toBe(
      (await development.check('user-1', 'read', resource)).allowed,
    )
  })
})
