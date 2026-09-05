import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { MAX_INHERITANCE_DEPTH, resolveEffectiveRoles, rolesToPolicy } from '../rbac'

const viewer: AccessControl.IRole = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [
    { action: 'read', resource: 'post' },
    { action: 'read', resource: 'comment' },
  ],
}

const editor: AccessControl.IRole = {
  id: 'editor',
  name: 'Editor',
  inherits: ['viewer'],
  permissions: [
    { action: 'create', resource: 'post' },
    { action: 'update', resource: 'post' },
  ],
}

const admin: AccessControl.IRole = {
  id: 'admin',
  name: 'Admin',
  inherits: ['editor'],
  permissions: [{ action: 'manage', resource: '*' }],
}

const scopedEditor: AccessControl.IRole = {
  id: 'org-editor',
  name: 'Org Editor',
  scope: 'org-1',
  permissions: [{ action: 'update', resource: 'post' }],
}

describe('resolveEffectiveRoles()', () => {
  const allRoles = [viewer, editor, admin]

  it('returns the assigned role itself', () => {
    expect(resolveEffectiveRoles(['viewer'], allRoles)).toContain('viewer')
  })

  it('includes inherited roles', () => {
    const effective = resolveEffectiveRoles(['editor'], allRoles)
    expect(effective).toContain('editor')
    expect(effective).toContain('viewer')
  })

  it('resolves deeply nested inheritance', () => {
    const effective = resolveEffectiveRoles(['admin'], allRoles)
    expect(effective).toContain('admin')
    expect(effective).toContain('editor')
    expect(effective).toContain('viewer')
  })

  it('handles unknown roles gracefully', () => {
    const effective = resolveEffectiveRoles(['nonexistent'], allRoles)
    expect(effective).toContain('nonexistent')
    expect(effective).toHaveLength(1)
  })

  it('handles circular inheritance', () => {
    const circA: AccessControl.IRole = { id: 'a', name: 'A', inherits: ['b'], permissions: [] }
    const circB: AccessControl.IRole = { id: 'b', name: 'B', inherits: ['a'], permissions: [] }
    const effective = resolveEffectiveRoles(['a'], [circA, circB])
    expect(effective).toContain('a')
    expect(effective).toContain('b')
    // should not hang or throw
  })

  it('deduplicates roles', () => {
    const effective = resolveEffectiveRoles(['admin', 'editor'], allRoles)
    const unique = [...new Set(effective)]
    expect(effective.length).toBe(unique.length)
  })
})

/**
 * PHANTOM ROLES. `resolveEffectiveRoles` used to add an inherited id to the
 * effective set before looking it up, so an id that no role defines still
 * reached `subject.roles`. It carried no permissions - there was no definition
 * to read any from - but that is only half of what `subject.roles` is used
 * for: a hand-written ABAC rule saying `subject.roles contains 'ghost'` fired
 * on it, and `getEffectiveRoles` reported the subject as holding a role that
 * does not exist.
 *
 * The operator route in is ordinary rather than exotic. `deleteRole` cascades
 * the role's *assignments* on every adapter, so the direct grant disappears;
 * an `inherits: ['ghost']` on some surviving role kept feeding the id back.
 * `validateRoles` already reports exactly this catalog as `DANGLING_INHERIT`
 * with `type: 'error'`.
 *
 * The depth-0 carve-out below is deliberate, not an oversight: a directly
 * assigned id is a row an operator wrote, and dropping it would narrow
 * `getEffectiveRoles` wherever the role catalog is not the only authority on
 * which ids exist. `handles unknown roles gracefully` above is its pin.
 */
describe('resolveEffectiveRoles() drops inherited ids that no role defines', () => {
  const ghostParent: AccessControl.IRole = { id: 'r', inherits: ['ghost'], name: 'R', permissions: [] }

  it('an inherited id with no definition does not reach the effective set', () => {
    expect(resolveEffectiveRoles(['r'], [ghostParent])).toEqual(['r'])
  })

  it('the surviving roles are unaffected by the dangling sibling', () => {
    const withReal: AccessControl.IRole = { id: 'r2', inherits: ['ghost', 'viewer'], name: 'R2', permissions: [] }
    expect(resolveEffectiveRoles(['r2'], [withReal, viewer]).sort()).toEqual(['r2', 'viewer'])
  })

  it('deleting a role removes its id from the set of anyone inheriting it', () => {
    // The before/after an operator actually observes: same assignment, same
    // `inherits`, only the definition goes away.
    const ghost: AccessControl.IRole = { id: 'ghost', name: 'Ghost', permissions: [] }
    expect(resolveEffectiveRoles(['r'], [ghostParent, ghost]).sort()).toEqual(['ghost', 'r'])
    expect(resolveEffectiveRoles(['r'], [ghostParent]).sort()).toEqual(['r'])
  })

  it('a dangling id deeper in the chain is dropped too', () => {
    const mid: AccessControl.IRole = { id: 'mid', inherits: ['ghost'], name: 'Mid', permissions: [] }
    const top: AccessControl.IRole = { id: 'top', inherits: ['mid'], name: 'Top', permissions: [] }
    expect(resolveEffectiveRoles(['top'], [top, mid]).sort()).toEqual(['mid', 'top'])
  })

  it('an id that is both dangling-inherited and directly assigned is kept', () => {
    // The assignment is the operator statement, so it wins over the drop -
    // and it must win regardless of which walk reaches the id first.
    expect(resolveEffectiveRoles(['r', 'ghost'], [ghostParent]).sort()).toEqual(['ghost', 'r'])
    expect(resolveEffectiveRoles(['ghost', 'r'], [ghostParent]).sort()).toEqual(['ghost', 'r'])
  })

  it('a chain that dangles at its root still yields the roles above it', () => {
    const a: AccessControl.IRole = { id: 'a', inherits: ['b'], name: 'A', permissions: [] }
    const b: AccessControl.IRole = { id: 'b', inherits: ['gone'], name: 'B', permissions: [] }
    expect(resolveEffectiveRoles(['a'], [a, b]).sort()).toEqual(['a', 'b'])
  })
})

describe('rolesToPolicy()', () => {
  it('converts roles into a policy with rules', () => {
    const policy = rolesToPolicy([viewer])
    expect(policy.id).toBe('__rbac__')
    expect(policy.algorithm).toBe('allow-overrides')
    expect(policy.rules).toHaveLength(2) // viewer has 2 permissions: read post, read comment
  })

  it('each permission becomes a rule with role membership condition', () => {
    const policy = rolesToPolicy([viewer])
    for (const rule of policy.rules) {
      expect(rule.effect).toBe('allow')
      // Each rule should require subject.roles contains the role id
      const conditions = 'all' in rule.conditions ? rule.conditions.all : []
      const hasRoleCheck = conditions.some(
        (c) => 'field' in c && c.field === 'subject.roles' && c.operator === 'contains',
      )
      expect(hasRoleCheck).toBe(true)
    }
  })

  it('inherits parent permissions', () => {
    const policy = rolesToPolicy([viewer, editor])
    // Editor's emitted rules carry "Editor:" in their description; inherited
    // viewer perms are emitted as separate rules under "Editor" because
    // collectPermissions flattens parent-first.
    const editorRules = policy.rules.filter((r) => r.description?.startsWith('Editor:'))
    // Editor should have: inherited viewer (read post, read comment) + own (create post, update post)
    expect(editorRules).toHaveLength(4)
    const editorActions = editorRules.map((r) => r.actions[0])
    expect(editorActions).toEqual(expect.arrayContaining(['read', 'read', 'create', 'update']))
  })

  it('adds scope condition for scoped roles', () => {
    const policy = rolesToPolicy([scopedEditor])
    const rules = policy.rules.filter((r) => r.description?.startsWith('Org Editor:'))
    expect(rules.length).toBe(1)

    const conditions = 'all' in rules[0]!.conditions ? rules[0]!.conditions.all : []
    const hasScopeCheck = conditions.some(
      (c) => 'field' in c && c.field === 'scope' && c.operator === 'eq' && c.value === 'org-1',
    )
    expect(hasScopeCheck).toBe(true)
  })

  it('wildcard scope does not add scope condition', () => {
    const globalRole: AccessControl.IRole = {
      id: 'global',
      name: 'Global',
      scope: '*',
      permissions: [{ action: 'read', resource: 'post' }],
    }
    const policy = rolesToPolicy([globalRole])
    const conditions = 'all' in policy.rules[0]!.conditions ? policy.rules[0]!.conditions.all : []
    const hasScopeCheck = conditions.some((c) => 'field' in c && c.field === 'scope')
    expect(hasScopeCheck).toBe(false)
  })

  it('permission-level conditions are merged into the rule', () => {
    const condRole: AccessControl.IRole = {
      id: 'cond-role',
      name: 'Conditional',
      permissions: [
        {
          action: 'update',
          resource: 'post',
          conditions: {
            all: [{ field: 'resource.attributes.ownerId', operator: 'eq', value: '$subject.id' }],
          },
        },
      ],
    }
    const policy = rolesToPolicy([condRole])
    const rule = policy.rules[0]!
    // Two siblings: the generated base group, then the author's group whole.
    // The author's group sits one level down whatever its key is, so an `any`
    // permission condition is not charged a level that an `all` one escapes.
    const top = 'all' in rule.conditions ? rule.conditions.all : []
    expect(top).toHaveLength(2)
    const fields = JSON.stringify(top)
    expect(fields).toContain('subject.roles')
    expect(fields).toContain('resource.attributes.ownerId')
  })
})

describe('rule id stability', () => {
  // IamAdapter ETags and external caches key on `rule.id`. Lock the format so
  // any change is intentional and shows up as a failing test.
  it('emits ids in the `__rbac__#N` shape', () => {
    const policy = rolesToPolicy([viewer])
    expect(policy.rules.map((r) => r.id)).toEqual(['__rbac__#0', '__rbac__#1'])
  })

  it('produces identical id sequence for identical input on repeated calls', () => {
    const a = rolesToPolicy([viewer, editor]).rules.map((r) => r.id)
    const b = rolesToPolicy([viewer, editor]).rules.map((r) => r.id)
    expect(a).toEqual(b)
  })

  it('emits unique ids even when role / action / resource names contain dots', () => {
    const dotted: AccessControl.IRole = {
      id: 'org.admin',
      name: 'Org Admin',
      permissions: [
        { action: 'post.update', resource: 'dashboard.users' },
        { action: 'post.delete', resource: 'dashboard.users' },
      ],
    }
    const ids = rolesToPolicy([dotted]).rules.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})

describe('inheritance-depth bound', () => {
  it('pins MAX_INHERITANCE_DEPTH at 32', () => {
    expect(MAX_INHERITANCE_DEPTH).toBe(32)
  })

  it('resolveEffectiveRoles returns without throwing on a 1000-deep linear chain', () => {
    // Bound at 32 means traversal stops cleanly; we only assert no stack overflow / no hang.
    const roles: AccessControl.IRole[] = []
    for (let i = 0; i < 1000; i++) {
      roles.push({
        id: `r${i}`,
        name: `R${i}`,
        permissions: [],
        ...(i > 0 ? { inherits: [`r${i - 1}`] } : {}),
      })
    }
    const effective = resolveEffectiveRoles(['r999'], roles)
    // Walk stops at MAX_INHERITANCE_DEPTH (32) deep from the start role.
    expect(effective.length).toBeLessThanOrEqual(34)
    expect(effective.length).toBeGreaterThan(1)
  })

  it('rolesToPolicy bounds permission collection on a deep linear chain', () => {
    const depth = 200
    const roles: AccessControl.IRole[] = []
    for (let i = 0; i < depth; i++) {
      roles.push({
        id: `r${i}`,
        name: `R${i}`,
        permissions: [{ action: `act${i}`, resource: 'post' }],
        ...(i > 0 ? { inherits: [`r${i - 1}`] } : {}),
      })
    }
    // Rules emitted for the deepest role only: its own permission plus at most
    // MAX_INHERITANCE_DEPTH inherited ones, never all 200.
    const deepest = rolesToPolicy(roles).rules.filter((r) => r.description?.startsWith(`R${depth - 1}: `))
    expect(deepest.length).toBeLessThanOrEqual(34)
    expect(deepest.length).toBeGreaterThan(1)
  })

  it('rolesToPolicy terminates on a cyclic inherits graph without duplicating permissions', () => {
    const a: AccessControl.IRole = {
      id: 'a',
      inherits: ['b'],
      name: 'A',
      permissions: [{ action: 'read', resource: 'post' }],
    }
    const b: AccessControl.IRole = {
      id: 'b',
      inherits: ['a'],
      name: 'B',
      permissions: [{ action: 'write', resource: 'post' }],
    }
    const rules = rolesToPolicy([a, b]).rules
    // a: [b.write, a.read]; b: [a.read, b.write] - four rules, no runaway.
    expect(rules).toHaveLength(4)
    expect(new Set(rules.map((r) => r.id)).size).toBe(4)
  })
})
