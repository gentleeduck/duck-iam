import { describe, expect, it, vi } from 'vitest'
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
  it('RBAC mask-covered request: production and development engines agree', async () => {
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

describe("production mode: 'and'-mode soundness - an irrelevant untargeted policy no longer vetoes a role grant", () => {
  it('an irrelevant second untargeted policy abstains, so the role permission still holds', async () => {
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
    // Under 'and', `irrelevant` has no rule shaped for update/post, so it abstains
    // (NotApplicable) instead of forcing a defaultEffect vote - the role grant is the only
    // applicable vote and stands.
    expect(await production.can('user-1', 'update', { type: 'post', attributes: {} })).toBe(true)
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
          { action: 'update', resource: 'post', scope: 'org-1' }, // rbacDynamic, unrelated cell
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

describe('role count beyond the 32-bit mask capacity', () => {
  // The bug this guards is bit-index aliasing: with `1 << 32` wrapping to bit 0,
  // role-32 would silently borrow role-0's grants. The engine no longer answers
  // that by denying everything - it falls back to the interpreter, which has no
  // mask and therefore no aliasing. The property under test is unchanged; only
  // the mechanism that delivers it is.
  const tooManyRoles = Array.from({ length: 33 }, (_, i) => ({
    id: `role-${i}`,
    name: `Role ${i}`,
    permissions: i === 0 ? [{ action: 'delete', resource: 'secret' }] : [],
  }))
  const overLimitAdapter = () =>
    new IamMemoryAdapter({
      roles: tooManyRoles,
      policies: [],
      assignments: { guest: ['role-32'], root: ['role-0'] },
      attributes: { guest: {}, root: {} },
    })

  const engineOf = (mode: 'development' | 'production') =>
    new IamEngine({ adapter: overLimitAdapter(), defaultEffect: 'deny', mode })

  it.each(['development', 'production'] as const)('does not alias role-32 onto role-0 (mode: %s)', async (mode) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const engine = engineOf(mode)
      const secret = { type: 'secret', attributes: {} }
      // role-32 has no permissions of its own, so this must deny - and it
      // must deny for that reason, not because the whole engine is down.
      expect(await engine.can('guest', 'delete', secret)).toBe(false)
      // The proof that it is not a blanket deny: role-0's real grant still
      // works over the same over-limit config.
      expect(await engine.can('root', 'delete', secret)).toBe(true)
    } finally {
      warn.mockRestore()
    }
  })

  it('production and development agree over an over-limit config', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const production = engineOf('production')
      // Not `engineOf('development')`: a helper parameterised over the mode
      // widens `TMode` to a union, which drops `check()`'s development-only
      // `IDecision` return type.
      const development = new IamEngine({ adapter: overLimitAdapter(), defaultEffect: 'deny', mode: 'development' })
      const secret = { type: 'secret', attributes: {} }
      for (const subject of ['guest', 'root']) {
        expect(await production.can(subject, 'delete', secret)).toBe(
          (await development.check(subject, 'delete', secret)).allowed,
        )
      }
    } finally {
      warn.mockRestore()
    }
  })
})
