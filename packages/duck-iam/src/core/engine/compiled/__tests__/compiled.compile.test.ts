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

describe('compileTable: basic classification', () => {
  it('compiles a role permission into the RBAC grant mask (kind stays untouched - RBAC is a separate vote)', () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    // No ABAC flat policy touches read/post, so the ABAC-only `kind`/`touched`
    // classification never sees this cell - only the RBAC mask does.
    expect(t.touched[idx]).toBe(0)
    expect(t.kind[idx]).toBe(CellKind.CONST_DENY)
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

  it('marks an ABAC-policy-covered cell as touched (touched is ABAC-only; RBAC-only cells stay untouched)', () => {
    const t = compileTable(roles, policies, 'allow-overrides')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('comment')!
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

  it('a policy with a wildcarded target is fully residual (excluded from the action/resource universe)', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['*'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.actionId.has('read')).toBe(false)
    expect(t.residualPolicies.map((p) => p.id)).toContain('targeted')
  })

  it('a literal action target that permits the rule compiles in as flat, not residual', () => {
    // policies[0]'s rule is actions:['read'], resources:['comment'] - the target permits 'read'.
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['read'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.residualPolicies.map((p) => p.id)).not.toContain('targeted')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('comment')!
    expect(t.kind[idx]).toBe(CellKind.CONST_ALLOW)
  })

  it("a literal target that excludes the rule's own action compiles in but leaves that cell untouched", () => {
    // policies[0]'s rule action is 'read' - a target of only 'update' permits none of it.
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['update'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.residualPolicies.map((p) => p.id)).not.toContain('targeted')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('comment')!
    expect(t.touched[idx]).toBe(0)
  })

  it('a literal resource target that permits the rule compiles in as flat, not residual', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { resources: ['comment'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.residualPolicies.map((p) => p.id)).not.toContain('targeted')
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('comment')!
    expect(t.kind[idx]).toBe(CellKind.CONST_ALLOW)
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

describe('compileTable: role scope/conditions compile into rbacDynamic (literal action+resource, not wildcarded)', () => {
  it('a permission with conditions gets a cell and lands in rbacDynamic, not rbacResidual', () => {
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
    expect(t.actionId.has('update')).toBe(true)
    expect(t.rbacResidual).toBeNull()
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    expect(t.rbacDynamic[idx]).toHaveLength(1)
    expect(t.rbacDynamic[idx]![0]!.conditions).toBeDefined()
    expect(t.rbacDynamic[idx]![0]!.scope).toBeUndefined()
  })

  it('a permission with a scope gets a cell and lands in rbacDynamic, not rbacResidual', () => {
    const scopedRoles: AccessControl.IRole[] = [
      { id: 'org-admin', name: 'Org Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
    ]
    const t = compileTable(scopedRoles, [], 'and')
    expect(t.actionId.has('update')).toBe(true)
    expect(t.rbacResidual).toBeNull()
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('org')!
    expect(t.rbacDynamic[idx]).toHaveLength(1)
    expect(t.rbacDynamic[idx]![0]!.scope).toBe('org-1')
    expect(t.rbacDynamic[idx]![0]!.conditions).toBeUndefined()
  })

  it('a plain permission (no scope/conditions) still takes the fast mask path, not rbacDynamic', () => {
    const t = compileTable(roles, [], 'and')
    expect(t.actionId.has('read')).toBe(true)
    expect(t.rbacResidual).toBeNull()
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!
    expect(t.rbacDynamic[idx]).toBeUndefined()
  })

  it('a wildcarded permission (action: *) is excluded from the cell universe and stays in rbacResidual', () => {
    const wildRoles: AccessControl.IRole[] = [
      { id: 'super', name: 'Super', permissions: [{ action: '*', resource: 'post' }] },
    ]
    const t = compileTable(wildRoles, [], 'and')
    expect(t.actionId.has('*')).toBe(false)
    expect(t.rbacResidual).not.toBeNull()
  })

  it('rbacDynamic group carries the inheritance-expanded role mask (same math as the allow bake)', () => {
    const inheritedRoles: AccessControl.IRole[] = [
      { id: 'base', name: 'Base', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
      { id: 'child', name: 'Child', inherits: ['base'], permissions: [] },
    ]
    const t = compileTable(inheritedRoles, [], 'and')
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('org')!
    const group = t.rbacDynamic[idx]![0]!
    const baseBit = 1 << t.roleId.get('base')!
    const childBit = 1 << t.roleId.get('child')!
    expect(group.roleMask & baseBit).not.toBe(0)
    expect(group.roleMask & childBit).not.toBe(0)
  })

  it('rbacDynamic groups from different roles at the same cell each carry their own scope', () => {
    const multiRoles: AccessControl.IRole[] = [
      { id: 'org1-admin', name: 'Org1 Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
      { id: 'org2-admin', name: 'Org2 Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-2' }] },
    ]
    const t = compileTable(multiRoles, [], 'and')
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('org')!
    const scopes = t.rbacDynamic[idx]!.map((g) => g.scope).sort()
    expect(scopes).toEqual(['org-1', 'org-2'])
  })
})

describe('compileTable: rbacResidual is never a member of residualPolicies (it is a separate vote, see compiled.lookup)', () => {
  it('a table with only wildcarded role permissions keeps rbacResidual out of residualPolicies', () => {
    const wildRoles: AccessControl.IRole[] = [
      { id: 'super', name: 'Super', permissions: [{ action: '*', resource: 'post' }] },
    ]
    const t = compileTable(wildRoles, [], 'and')
    expect(t.rbacResidual).not.toBeNull()
    expect(t.residualPolicies.map((p) => p.id)).not.toContain('__rbac__')
    expect(t.residualPolicies).toHaveLength(0)
  })
})

describe('compileTable: hasRbacSource is true from rbacDynamic-only permissions (no simple, no wildcard-residual)', () => {
  it('a role with only a scoped permission still reports hasRbacSource', () => {
    const scopedRoles: AccessControl.IRole[] = [
      { id: 'org-admin', name: 'Org Admin', permissions: [{ action: 'update', resource: 'org', scope: 'org-1' }] },
    ]
    const t = compileTable(scopedRoles, [], 'and')
    expect(t.hasRbacSource).toBe(true)
  })
})

describe('compileTable: role count limit', () => {
  it('throws when the role count exceeds the 32-bit mask capacity', () => {
    const tooManyRoles: AccessControl.IRole[] = Array.from({ length: 33 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: [],
    }))
    expect(() => compileTable(tooManyRoles, [], 'and')).toThrow(/32/)
  })

  it('accepts exactly 32 roles', () => {
    const roles32: AccessControl.IRole[] = Array.from({ length: 32 }, (_, i) => ({
      id: `role-${i}`,
      name: `Role ${i}`,
      permissions: [],
    }))
    expect(() => compileTable(roles32, [], 'and')).not.toThrow()
  })
})

describe('compileTable: hasFlatSource / hasRbacSource bookkeeping', () => {
  it('a table with only residual policies has no ABAC flat source', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['*'] } }]
    const t = compileTable([], targeted, 'and')
    expect(t.hasFlatSource).toBe(false)
  })

  it('a table with a flat-eligible ABAC policy has a flat source', () => {
    const t = compileTable([], policies, 'and')
    expect(t.hasFlatSource).toBe(true)
  })

  it('hasRbacSource is false when no role has any permission', () => {
    const t = compileTable([{ id: 'empty', name: 'Empty', permissions: [] }], [], 'and')
    expect(t.hasRbacSource).toBe(false)
  })

  it('hasRbacSource is true from a simple permission alone', () => {
    const t = compileTable(roles, [], 'and')
    expect(t.hasRbacSource).toBe(true)
  })

  it('hasRbacSource is true from a conditioned (rbacDynamic-only) permission alone', () => {
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
    expect(t.hasRbacSource).toBe(true)
  })
})
