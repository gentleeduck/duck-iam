import { describe, expect, it } from 'vitest'
import { MAX_CONDITION_DEPTH } from '../../conditions/conditions.libs'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamRequest } from '../../types'
import { validateRole } from '../../validate'
import { rolesToPolicy } from '../rbac'

/**
 * `rolesToPolicy` spliced an `all` permission condition into the generated
 * rule's own `all` (depth-neutral) but nested `any` and `none` one level
 * deeper. The identical tree therefore crossed `MAX_CONDITION_DEPTH` in one
 * shape and not the other, and the deeper shape then failed closed at runtime
 * with no validation error - role permissions are allow-only, so that is a
 * silent denial.
 */
type Group = AccessControl.IConditionGroup

/** A group of `wrappers` nesting levels, ending in one leaf that is true. */
function nest(key: 'all' | 'any', wrappers: number): Group {
  const leaf = { field: 'subject.id', operator: 'eq' as const, value: 'u1' }
  let node: Group = key === 'all' ? { all: [leaf] } : { any: [leaf] }
  for (let i = 1; i < wrappers; i++) node = key === 'all' ? { all: [node] } : { any: [node] }
  return node
}

function roleWith(conditions: Group): AccessControl.IRole {
  return {
    id: 'r',
    name: 'R',
    permissions: [{ action: 'read', conditions, resource: 'post' }],
  }
}

const request: IamRequest.IAccessRequest = {
  action: 'read',
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: ['r'] },
}

function grants(role: AccessControl.IRole): boolean {
  return evaluate([rolesToPolicy([role])], request, 'deny', 'and').allowed
}

describe('an `any` permission condition costs the same depth as an `all` one', () => {
  for (let wrappers = 1; wrappers <= MAX_CONDITION_DEPTH + 1; wrappers++) {
    it(`agrees at ${wrappers} wrapper(s)`, () => {
      expect(grants(roleWith(nest('any', wrappers)))).toBe(grants(roleWith(nest('all', wrappers))))
    })
  }

  it('validateRole agrees with the evaluator on both shapes', () => {
    for (let wrappers = 1; wrappers <= MAX_CONDITION_DEPTH + 1; wrappers++) {
      for (const key of ['all', 'any'] as const) {
        const role = roleWith(nest(key, wrappers))
        expect(validateRole(role).valid).toBe(grants(role))
      }
    }
  })

  it('validateRole accepts and rejects the two shapes identically', () => {
    for (let wrappers = 1; wrappers <= MAX_CONDITION_DEPTH + 1; wrappers++) {
      expect(validateRole(roleWith(nest('any', wrappers))).valid).toBe(
        validateRole(roleWith(nest('all', wrappers))).valid,
      )
    }
  })

  // Control: a shallow condition of either shape still grants, so the parity
  // above is not "both always deny".
  it('still grants on a shallow condition of either shape', () => {
    expect(grants(roleWith(nest('all', 1)))).toBe(true)
    expect(grants(roleWith(nest('any', 1)))).toBe(true)
  })

  // Control: a condition that does not hold still denies.
  it('still denies when the condition is false', () => {
    expect(grants(roleWith({ all: [{ field: 'subject.id', operator: 'eq', value: 'someone-else' }] }))).toBe(false)
  })
})

describe('the author group is passed through whole, whatever its key', () => {
  const leaf = { field: 'subject.id', operator: 'eq' as const, value: 'u1' }
  const shapes: Group[] = [{ all: [leaf] }, { any: [leaf] }, { none: [leaf] }]

  it.each(shapes)('keeps %o intact', (conditions) => {
    const rule = rolesToPolicy([roleWith(conditions)]).rules[0]
    const top = rule && 'all' in rule.conditions ? rule.conditions.all : []
    expect(top).toHaveLength(2)
    expect(top[1]).toEqual(conditions)
  })

  it('an unrecognised group key still fails closed rather than being dropped', () => {
    // A typo'd key or a hand-edited row: the shared parser reads an unknown
    // group as `false`, so the grant never becomes unconditional.
    const typo: Group = JSON.parse('{"nope":[]}')
    expect(grants(roleWith(typo))).toBe(false)
  })
})
