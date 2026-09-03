import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { MAX_INHERITANCE_DEPTH, resolveEffectiveRoles, rolesToPolicy } from '../rbac'

/**
 * `inherits` is documented as a set of parents, so two role definitions that
 * are set-equal must resolve to the same permissions. They did not: one
 * `visited` set was shared across sibling branches and pinned a role to
 * whatever depth it was *first* reached at, so a role reached deep (near the
 * cut) blocked the later shallow path from expanding its ancestors. An adapter
 * returning `inherits` in a different order - JSON key order, SQL row order -
 * gave different authorization answers for the same graph.
 */
const CHAIN = MAX_INHERITANCE_DEPTH - 2

/**
 * `hub` reaches `hinge` two ways: down a long chain (depth CHAIN + 1, one step
 * short of the cut) and directly (depth 1). Only the shallow route leaves room
 * for `hinge`'s own three-deep chain, whose tail holds the only permission.
 */
function graph(hubInherits: string[]): AccessControl.IRole[] {
  const roles: AccessControl.IRole[] = [
    { id: 'hub', inherits: hubInherits, name: 'hub', permissions: [] },
    { id: 'hinge', inherits: ['y0'], name: 'hinge', permissions: [] },
    { id: 'y0', inherits: ['y1'], name: 'y0', permissions: [] },
    { id: 'y1', inherits: ['y2'], name: 'y1', permissions: [] },
    { id: 'y2', name: 'y2', permissions: [{ action: 'read', resource: 'secret' }] },
  ]
  for (let i = 0; i < CHAIN; i++) {
    roles.push({
      id: `d${i}`,
      inherits: [i === CHAIN - 1 ? 'hinge' : `d${i + 1}`],
      name: `d${i}`,
      permissions: [],
    })
  }
  return roles
}

const DEEP_FIRST = ['d0', 'hinge']
const SHALLOW_FIRST = ['hinge', 'd0']

describe('inheritance resolution does not depend on the order of `inherits`', () => {
  it('resolveEffectiveRoles returns the same set either way', () => {
    const deep = resolveEffectiveRoles(['hub'], graph(DEEP_FIRST)).sort()
    const shallow = resolveEffectiveRoles(['hub'], graph(SHALLOW_FIRST)).sort()
    expect(deep).toEqual(shallow)
    expect(deep).toContain('y2')
  })

  it('rolesToPolicy emits the deep tail permission either way', () => {
    const rulesFor = (order: string[]) =>
      rolesToPolicy(graph(order)).rules.filter((r) => r.resources.includes('secret')).length
    expect(rulesFor(DEEP_FIRST)).toBe(rulesFor(SHALLOW_FIRST))
    expect(rulesFor(DEEP_FIRST)).toBeGreaterThan(0)
  })

  // A re-reached role expands its ancestors again; its own permissions must not
  // be emitted a second time for the same holder.
  it('does not emit a role reached twice as duplicate permissions', () => {
    const rules = rolesToPolicy(graph(SHALLOW_FIRST)).rules.filter(
      (r) => r.resources.includes('secret') && JSON.stringify(r.conditions).includes('"hub"'),
    )
    expect(rules).toHaveLength(1)
  })

  // Controls: the depth cut must still cut, and a cycle must still terminate.
  it('still drops a chain that is genuinely past the cut from every route', () => {
    const roles: AccessControl.IRole[] = [{ id: 'r0', inherits: ['r1'], name: 'r0', permissions: [] }]
    const overflow = MAX_INHERITANCE_DEPTH + 3
    for (let i = 1; i <= overflow; i++) {
      roles.push({
        id: `r${i}`,
        inherits: i === overflow ? undefined : [`r${i + 1}`],
        name: `r${i}`,
        permissions: i === overflow ? [{ action: 'read', resource: 'secret' }] : [],
      })
    }
    expect(resolveEffectiveRoles(['r0'], roles)).not.toContain(`r${overflow}`)
  })

  it('terminates on a cycle', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'a', inherits: ['b'], name: 'a', permissions: [] },
      { id: 'b', inherits: ['a'], name: 'b', permissions: [{ action: 'read', resource: 'post' }] },
    ]
    expect(resolveEffectiveRoles(['a'], roles).sort()).toEqual(['a', 'b'])
    // One rule for `b`'s own permission, one for `a` inheriting it.
    expect(rolesToPolicy(roles).rules).toHaveLength(2)
  })
})
