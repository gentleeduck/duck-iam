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
})
