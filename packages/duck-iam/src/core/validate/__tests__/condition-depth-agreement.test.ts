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

/** `levels` nested groups wrapping a leaf that is true for `request`. */
function nest(levels: number): AccessControl.IConditionGroup {
  let node: AccessControl.IConditionGroup | AccessControl.ICondition = {
    field: 'subject.id',
    operator: 'eq',
    value: 'u1',
  }
  for (let i = 0; i < levels; i++) node = { all: [node] }
  return node as AccessControl.IConditionGroup
}

function validates(group: AccessControl.IConditionGroup): boolean {
  const issues: IamValidate.IIssue[] = []
  validateConditionGroup(group, 'conditions', issues, 0)
  return issues.length === 0
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
