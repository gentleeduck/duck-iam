import { describe, expect, it } from 'vitest'
import { evalConditionGroup } from '../../conditions/conditions'
import { MAX_CONDITION_DEPTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { validateConditionGroup } from '../validate.libs'
import type { IamValidate } from '../validate.types'

/**
 * The validator and the evaluator must agree on the nesting limit. The
 * evaluator refuses a group at `depth >= MAX_CONDITION_DEPTH` and fails closed,
 * so a validator using `>` accepted exactly one level deeper than the evaluator
 * would ever match. An allow rule at that depth merely stopped allowing, but a
 * deny rule validated cleanly and then silently stopped denying.
 */

const request: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, id: 'p1', type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

type GroupKey = 'all' | 'any' | 'none'

/** A group literal for `key`; a computed key would widen to an index signature. */
function wrap(key: GroupKey, items: readonly (AccessControl.IConditionGroup | AccessControl.ICondition)[]) {
  if (key === 'all') return { all: [...items] }
  if (key === 'any') return { any: [...items] }
  return { none: [...items] }
}

/** `levels` nested groups wrapping a leaf that is true for `request`, cycling `keys` outermost-first. */
function nest(levels: number, keys: readonly GroupKey[] = ['all']): AccessControl.IConditionGroup {
  const leaf: AccessControl.ICondition = { field: 'subject.id', operator: 'eq', value: 'u1' }
  const keyAt = (index: number): GroupKey => keys[index % keys.length] ?? 'all'
  let node: AccessControl.IConditionGroup = wrap(keyAt(levels - 1), [leaf])
  for (let i = levels - 2; i >= 0; i--) node = wrap(keyAt(i), [node])
  return node
}

function validates(group: AccessControl.IConditionGroup): boolean {
  const issues: IamValidate.IIssue[] = []
  validateConditionGroup(group, 'conditions', issues, 0)
  return issues.length === 0
}

/** The shallowest nesting the validator refuses, per key shape. */
function firstRefusedDepth(keys: readonly GroupKey[]): number {
  for (let levels = 1; levels <= MAX_CONDITION_DEPTH + 5; levels++) {
    if (!validates(nest(levels, keys))) return levels
  }
  return -1
}

describe('condition nesting limit agrees between validator and evaluator', () => {
  for (let levels = MAX_CONDITION_DEPTH - 2; levels <= MAX_CONDITION_DEPTH + 2; levels++) {
    it(`${levels} nested groups: accepted by the validator iff matched by the evaluator`, () => {
      const group = nest(levels)
      expect(validates(group)).toBe(evalConditionGroup(request, group, 0))
    })
  }

  it('reports LIMIT_EXCEEDED at the first depth the evaluator refuses', () => {
    const tooDeep = nest(MAX_CONDITION_DEPTH + 1)
    const issues: IamValidate.IIssue[] = []
    validateConditionGroup(tooDeep, 'conditions', issues, 0)

    expect(issues.some((i) => i.code === 'LIMIT_EXCEEDED')).toBe(true)
    expect(evalConditionGroup(request, tooDeep, 0)).toBe(false)
  })

  it('a deny rule at the boundary cannot validate and then stop denying', () => {
    // The dangerous shape: validation passes, evaluation silently returns false.
    for (let levels = 1; levels <= MAX_CONDITION_DEPTH + 3; levels++) {
      const group = nest(levels)
      const accepted = validates(group)
      const matched = evalConditionGroup(request, group, 0)
      expect(accepted && !matched).toBe(false)
    }
  })
})

/**
 * Every case above builds `{ all: [...] }`. `evalConditionGroup` reaches its
 * depth guard before it looks at the key, and `validateConditionGroup` counts
 * the same way, so the boundary is supposed to be key-independent - but nothing
 * said so, and the two functions pick the key apart in different places.
 */
describe('the limit is the same for any and none, and for a mixed tree', () => {
  // `none` inverts its child's verdict, so the accepted-iff-matched equivalence
  // is stated only for the truth-preserving keys; `none` gets the structural
  // and fail-closed assertions below instead.
  describe.each<readonly GroupKey[]>([['any'], ['all', 'any'], ['any', 'all']])('keys %j', (...keys) => {
    const shape = keys.flat()
    for (let levels = MAX_CONDITION_DEPTH - 1; levels <= MAX_CONDITION_DEPTH + 1; levels++) {
      it(`${levels} nested groups: accepted by the validator iff matched by the evaluator`, () => {
        const group = nest(levels, shape)
        expect(validates(group)).toBe(evalConditionGroup(request, group, 0))
      })
    }
  })

  it.each<readonly GroupKey[]>([['all'], ['any'], ['none'], ['all', 'any', 'none']])(
    'first refuses at MAX_CONDITION_DEPTH + 1 for keys %j',
    (...keys) => {
      expect(firstRefusedDepth(keys.flat())).toBe(MAX_CONDITION_DEPTH + 1)
    },
  )

  /**
   * `none` is the key where a truncated group is dangerous in the other
   * direction: "allow unless X" is written `{ none: [X] }`, so a group that
   * stops evaluating must not report that X was absent.
   */
  it('a too-deep none group fails closed rather than reporting its child absent', () => {
    const tooDeep = nest(MAX_CONDITION_DEPTH + 1, ['none'])
    expect(validates(tooDeep)).toBe(false)
    expect(evalConditionGroup(request, tooDeep, 0)).toBe(false)
  })

  // Control: one level shallower the same `none` tree is accepted and does
  // evaluate, so the assertion above is about the depth and not about `none`.
  // Each `none` inverts, so a tree of an even number of them reports its true
  // leaf as true - the verdict a truncated tree must not be confused with.
  it('control: a none tree inside the limit still evaluates', () => {
    const group = nest(MAX_CONDITION_DEPTH, ['none'])
    expect(validates(group)).toBe(true)
    expect(evalConditionGroup(request, group, 0)).toBe(MAX_CONDITION_DEPTH % 2 === 0)
  })
})
