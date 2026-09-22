import { describe, expect, it } from 'vitest'
import { evalConditionGroup } from '../../conditions/conditions'
import { MAX_CONDITION_DEPTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { validateConditionGroup } from '../validate.libs'
import type { IamValidate } from '../validate.types'

// Validator and evaluator agree on the nesting limit: the evaluator fails closed at `depth >= MAX_CONDITION_DEPTH`,
// so an off-by-one validator would accept a deny rule that never denies.

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

/** The evaluator's answer with refusal as a third outcome, so "the leaf did not match" differs from "gave up". */
function evaluates(group: AccessControl.IConditionGroup): boolean | 'refused' {
  try {
    return evalConditionGroup(request, group, 0)
  } catch {
    return 'refused'
  }
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
      // Accepted iff evaluable, and when evaluable the leaf is true - so the
      // two sides agree on both the boundary and the verdict.
      expect(validates(group)).toBe(evaluates(group) === true)
    })
  }

  it('reports LIMIT_EXCEEDED at the first depth the evaluator refuses', () => {
    const tooDeep = nest(MAX_CONDITION_DEPTH + 1)
    const issues: IamValidate.IIssue[] = []
    validateConditionGroup(tooDeep, 'conditions', issues, 0)

    expect(issues.some((i) => i.code === 'LIMIT_EXCEEDED')).toBe(true)
    expect(evaluates(tooDeep)).toBe('refused')
  })

  it('a deny rule at the boundary cannot validate and then stop denying', () => {
    // SECURITY: never accepted-but-not-matched, which retires a deny rule. A refusal is safe: it makes the policy
    // Indeterminate, and a deny-bearing policy votes deny.
    for (let levels = 1; levels <= MAX_CONDITION_DEPTH + 3; levels++) {
      const group = nest(levels)
      expect(validates(group) && evaluates(group) !== true).toBe(false)
    }
  })
})

// Both functions check depth before reading the key, so the boundary must not depend on which key is used.
describe('the limit is the same for any and none, and for a mixed tree', () => {
  // `none` inverts its child, so accepted-iff-matched holds only for truth-preserving keys; `none` is covered below.
  describe.each<readonly GroupKey[]>([['any'], ['all', 'any'], ['any', 'all']])('keys %j', (...keys) => {
    const shape = keys.flat()
    for (let levels = MAX_CONDITION_DEPTH - 1; levels <= MAX_CONDITION_DEPTH + 1; levels++) {
      it(`${levels} nested groups: accepted by the validator iff matched by the evaluator`, () => {
        const group = nest(levels, shape)
        expect(validates(group)).toBe(evaluates(group) === true)
      })
    }
  })

  it.each<readonly GroupKey[]>([['all'], ['any'], ['none'], ['all', 'any', 'none']])(
    'first refuses at MAX_CONDITION_DEPTH + 1 for keys %j',
    (...keys) => {
      expect(firstRefusedDepth(keys.flat())).toBe(MAX_CONDITION_DEPTH + 1)
    },
  )

  // SECURITY: "allow unless X" is `{ none: [X] }`, so a group that stops evaluating must not report X absent.
  it('a too-deep none group is refused rather than reporting its child absent', () => {
    // Refusal is the only answer `none` cannot invert into a grant.
    const tooDeep = nest(MAX_CONDITION_DEPTH + 1, ['none'])
    expect(validates(tooDeep)).toBe(false)
    expect(evaluates(tooDeep)).toBe('refused')
  })

  // Control: one level shallower the same tree evaluates, so the test above is about depth, not `none`. An even
  // number of `none`s reports the true leaf as true.
  it('control: a none tree inside the limit still evaluates', () => {
    const group = nest(MAX_CONDITION_DEPTH, ['none'])
    expect(validates(group)).toBe(true)
    expect(evalConditionGroup(request, group, 0)).toBe(MAX_CONDITION_DEPTH % 2 === 0)
  })
})
