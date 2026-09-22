import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import { iamBuildPermissionKey } from '../../../../shared/keys'
import { IamEngine } from '../../engine'

// Production (compiled table) vs development (interpreter) verdicts over the same data, per `policyCombine`.
// Each case also pins the development verdict, so two engines that deny everything cannot agree vacuously.

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
      mode: 'development',
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      policyCombine,
    })
    const resource = { type: 'post', attributes: {} }
    // `editor` grants `update post` and the ownership policy has no `update` rule, so it abstains under both combines.
    expect((await development.check('user-1', 'update', resource)).allowed).toBe(true)
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
      mode: 'development',
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      policyCombine,
    })
    const owned = { type: 'post', attributes: { ownerId: 'user-1' } }
    const notOwned = { type: 'post', attributes: { ownerId: 'someone-else' } }
    // The owned/notOwned split proves the condition ran. Allowed under 'and' too: `editor` has no `read post`,
    // so RBAC abstains and the ownership allow is the only vote.
    expect((await development.check('user-1', 'read', owned)).allowed).toBe(true)
    expect((await development.check('user-1', 'read', notOwned)).allowed).toBe(false)
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
      mode: 'development',
      adapter: new IamMemoryAdapter({ roles, policies, assignments, attributes }),
      defaultEffect: 'deny',
      policyCombine,
    })
    const checks = [
      { action: 'update', resource: 'post' },
      { action: 'read', resource: 'post', resourceId: 'p1' },
    ] as const
    const prodMap = await production.permissions('user-1', checks)
    // Guard against a `permissions()` that denies every key passing the loop below vacuously.
    expect(prodMap[iamBuildPermissionKey('update', 'post')]).toBe(true)
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
    // `irrelevant` has no update/post rule, so it abstains instead of voting defaultEffect.
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
      mode: 'development',
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
  // `1 << 32` wraps to bit 0, so role-32 would borrow role-0's grants. Past 32 roles the engine uses the interpreter.
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
      // role-32 has no permissions of its own, so this must deny.
      expect(await engine.can('guest', 'delete', secret)).toBe(false)
      // Not a blanket deny: role-0's real grant still works over the same config.
      expect(await engine.can('root', 'delete', secret)).toBe(true)
    } finally {
      warn.mockRestore()
    }
  })

  it('production and development agree over an over-limit config', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const production = engineOf('production')
      // Not `engineOf('development')`: its `TMode` union drops `check()`'s development-only `IDecision` type.
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
