import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../../types'
import { CellKind, compileTable } from '../compiled.compile'

const roles: AccessControl.IRole[] = [
  { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
  { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [{ action: 'update', resource: 'post' }] },
]

const policies: AccessControl.IPolicy[] = [
  {
    id: 'public',
    name: 'Public',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'pub-read',
        effect: 'allow',
        priority: 0,
        actions: ['read'],
        resources: ['comment'],
        conditions: { all: [] },
      },
    ],
  },
]

describe('compileTable: basic classification (allow-overrides: unaffected by forceAndDynamic)', () => {
  it('compiles a role permission to ROLE_MASK', () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.ROLE_MASK)
    const viewerBit = 1 << t.roleId.get('viewer')!
    expect(t.allow[idx]! & viewerBit).not.toBe(0)
  })

  it("closes role inheritance: editor holds viewer's grant too", () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    const editorBit = 1 << t.roleId.get('editor')!
    expect(t.allow[idx]! & editorBit).not.toBe(0)
  })

  it('compiles an unconditional ABAC allow rule to CONST_ALLOW', () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('comment')!
    expect(t.kind[idx]).toBe(CellKind.CONST_ALLOW)
  })

  it('marks a cell no rule or permission ever touched as untouched', () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('comment')!
    expect(t.touched[idx]).toBe(0)
  })

  it('marks a role-covered cell as touched', () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    expect(t.touched[idx]).toBe(1)
  })

  it('conflicting allow/deny cells become DYNAMIC (not untouched) with both rules represented', () => {
    const conflictRoles: AccessControl.IRole[] = [{ id: 'viewer', name: 'Viewer', permissions: [] }]
    const conflictPolicies: AccessControl.IPolicy[] = [
      {
        id: 'conflict',
        name: 'Conflict',
        algorithm: 'deny-overrides',
        rules: [
          { id: 'r1', effect: 'allow', priority: 0, actions: ['read'], resources: ['secret'], conditions: { all: [] } },
          { id: 'r2', effect: 'deny', priority: 0, actions: ['read'], resources: ['secret'], conditions: { all: [] } },
        ],
      },
    ]
    const t = compileTable(conflictRoles, conflictPolicies, 'allow-overrides')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('secret')!
    expect(t.touched[idx]).toBe(1)
    expect(t.kind[idx]).toBe(CellKind.DYNAMIC)
    const groups = t.dynamic[idx]!
    expect(groups).toHaveLength(1)
    expect(groups[0]!.rules.map((r) => r.id).sort()).toEqual(['r1', 'r2'])
  })

  it('a policy with targets is fully residual (excluded from the action/resource universe)', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['update'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.actionId.has('read')).toBe(false)
    expect(t.residualPolicies.map((p) => p.id)).toContain('targeted')
  })

  it('a rule with a wildcard action (post:*) makes the whole policy residual, not silently inert', () => {
    const wildcardPolicies: AccessControl.IPolicy[] = [
      {
        id: 'wild',
        name: 'Wild',
        algorithm: 'deny-overrides',
        rules: [
          { id: 'w', effect: 'allow', priority: 0, actions: ['post:*'], resources: ['thing'], conditions: { all: [] } },
        ],
      },
    ]
    const t = compileTable([], wildcardPolicies, 'and')
    expect(t.actionId.has('post:*')).toBe(false)
    expect(t.residualPolicies.map((p) => p.id)).toContain('wild')
  })

  it('a rule with a wildcard resource (org.*) makes the whole policy residual', () => {
    const wildcardPolicies: AccessControl.IPolicy[] = [
      {
        id: 'wild',
        name: 'Wild',
        algorithm: 'deny-overrides',
        rules: [
          { id: 'w', effect: 'allow', priority: 0, actions: ['read'], resources: ['org.*'], conditions: { all: [] } },
        ],
      },
    ]
    const t = compileTable([], wildcardPolicies, 'and')
    expect(t.resourceId.has('org.*')).toBe(false)
    expect(t.residualPolicies.map((p) => p.id)).toContain('wild')
  })
})

describe('compileTable: role scope/conditions routing to the residual RBAC policy', () => {
  it('a permission with conditions does not get an unconditional ROLE_MASK bit', () => {
    const conditionalRoles: AccessControl.IRole[] = [
      {
        id: 'owner',
        name: 'Owner',
        permissions: [
          {
            action: 'update',
            resource: 'post',
            conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] },
          },
        ],
      },
    ]
    const t = compileTable(conditionalRoles, [], 'and')
    // Never entered the fast-bit universe: no policy/role produced a simple grant here.
    expect(t.actionId.has('update')).toBe(false)
    const rbac = t.residualPolicies.find((p) => p.id === '__rbac__')
    expect(rbac).toBeDefined()
    expect(rbac!.rules).toHaveLength(1)
  })

  it('a permission with a scope does not get an unconditional ROLE_MASK bit', () => {
    const scopedRoles: AccessControl.IRole[] = [
      { id: 'org-admin', name: 'Org Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
    ]
    const t = compileTable(scopedRoles, [], 'and')
    expect(t.actionId.has('update')).toBe(false)
    const rbac = t.residualPolicies.find((p) => p.id === '__rbac__')
    expect(rbac).toBeDefined()
    expect(rbac!.rules).toHaveLength(1)
  })

  it('a plain permission (no scope/conditions) still takes the fast ROLE_MASK path', () => {
    const t = compileTable(roles, [], 'and')
    expect(t.actionId.has('read')).toBe(true)
    const rbac = t.residualPolicies.find((p) => p.id === '__rbac__')
    expect(rbac).toBeUndefined()
  })

  it('inheritance through a role with only complex permissions still resolves for the residual RBAC policy', () => {
    const inheritedRoles: AccessControl.IRole[] = [
      {
        id: 'base',
        name: 'Base',
        permissions: [
          {
            action: 'delete',
            resource: 'post',
            conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] },
          },
        ],
      },
      { id: 'child', name: 'Child', inherits: ['base'], permissions: [] },
    ]
    const t = compileTable(inheritedRoles, [], 'and')
    const rbac = t.residualPolicies.find((p) => p.id === '__rbac__')
    expect(rbac).toBeDefined()
    // The permission is reachable both directly (holding 'base') and via inheritance
    // (holding 'child', which inherits 'base') - rolesToPolicy emits one rule per path.
    expect(rbac!.rules.some((r) => JSON.stringify(r.conditions).includes('base'))).toBe(true)
    expect(rbac!.rules.some((r) => JSON.stringify(r.conditions).includes('child'))).toBe(true)
  })
})

describe('compileTable: hasFlatSource / foldRbacIntoAnd bookkeeping', () => {
  it('a table with only residual policies has no flat source', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['read'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.hasFlatSource).toBe(false)
  })

  it('a table with a flat-eligible ABAC policy has a flat source', () => {
    const t = compileTable([], policies, 'and')
    expect(t.hasFlatSource).toBe(true)
  })

  it("foldRbacIntoAnd is false under 'allow-overrides' regardless of source count", () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    expect(t.foldRbacIntoAnd).toBe(false)
  })

  it("foldRbacIntoAnd is false under 'and' with a single flat source", () => {
    const t = compileTable(roles, [], 'and')
    expect(t.foldRbacIntoAnd).toBe(false)
  })

  it("foldRbacIntoAnd is true under 'and' with simple roles plus a flat ABAC policy", () => {
    const t = compileTable(roles, policies, 'and')
    expect(t.foldRbacIntoAnd).toBe(true)
  })
})
