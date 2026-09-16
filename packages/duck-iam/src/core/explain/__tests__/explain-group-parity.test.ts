import { describe, expect, it } from 'vitest'
import { evalConditionGroup } from '../../conditions/conditions'
import type { AccessControl, IamRequest } from '../../types'
import { explainEvaluation } from '../explain'
import type { Explain } from '../explain.types'

// A traced group must answer what `evalConditionGroup` answers: `{}` is "no conditions" and true, an unrecognised
// key is refused. Compared against the decision path itself, not a hand-written expectation.
const subjectInfo: Explain.ISubjectInfo = { originalRoles: [], scopedRolesApplied: [], subjectId: 'u1' }

const REQUEST: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

function policyWith(conditions: AccessControl.IConditionGroup): AccessControl.IPolicy {
  return {
    algorithm: 'first-match',
    id: 'p1',
    name: 'p1',
    rules: [{ actions: ['read'], conditions, effect: 'allow', id: 'r1', priority: 1, resources: ['post'] }],
  }
}

/** The traced group result as three outcomes; a boolean would hide a refusal, which is the drift this file is for. */
function tracedGroupResult(conditions: AccessControl.IConditionGroup): boolean | 'refused' {
  const result = explainEvaluation([policyWith(conditions)], REQUEST, 'deny', subjectInfo, 'and')
  const rule = result.policies[0]?.rules[0]
  if (rule === undefined) throw new Error('trace produced no rule')
  return rule.conditionError === undefined ? rule.conditions.result : 'refused'
}

/** The decision path's answer, in the same three outcomes. */
function decidedGroupResult(conditions: AccessControl.IConditionGroup): boolean | 'refused' {
  try {
    return evalConditionGroup(REQUEST, conditions, 0)
  } catch {
    return 'refused'
  }
}

/** A group whose keys the type does not describe, parsed from JSON so it arrives untyped, as a store row does. */
function malformedGroup(json: string): AccessControl.IConditionGroup {
  return JSON.parse(json)
}

describe('a traced condition group agrees with the group the engine decided on', () => {
  const cases: { name: string; group: AccessControl.IConditionGroup }[] = [
    { group: malformedGroup('{}'), name: 'an empty object is "no conditions"' },
    { group: { all: [] }, name: 'an empty all-group' },
    { group: { any: [] }, name: 'an empty any-group' },
    { group: { none: [] }, name: 'an empty none-group' },
    { group: malformedGroup('{"foo":1}'), name: 'an unrecognised key' },
    { group: malformedGroup('{"All":[]}'), name: 'a mis-cased all' },
    { group: malformedGroup('{"all":[],"bogus":true}'), name: 'a known key alongside an unknown one' },
  ]

  for (const { name, group } of cases) {
    it(`${name}: trace matches evalConditionGroup`, () => {
      expect(tracedGroupResult(group)).toBe(decidedGroupResult(group))
    })
  }

  it('the empty object specifically is true on both paths, not false', () => {
    // Pinned as an absolute: two paths agreeing on the wrong answer would satisfy the parity check above.
    const empty = malformedGroup('{}')
    expect(evalConditionGroup(REQUEST, empty, 0)).toBe(true)
    expect(tracedGroupResult(empty)).toBe(true)
  })

  it('an unrecognised key specifically is refused on both paths, not false', () => {
    // SECURITY: `false` here reads as fail-closed but is not - on a deny rule it retires the deny.
    const bogus = malformedGroup('{"foo":1}')
    expect(decidedGroupResult(bogus)).toBe('refused')
    expect(tracedGroupResult(bogus)).toBe('refused')
  })
})
