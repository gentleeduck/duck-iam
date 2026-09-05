import { describe, expect, it } from 'vitest'
import { evalConditionGroup } from '../../conditions/conditions'
import type { AccessControl, IamRequest } from '../../types'
import { explainEvaluation } from '../explain'
import type { Explain } from '../explain.types'

/**
 * The third explain/can drift, one level up from the leaf drift that
 * `explain-leaf-parity.test.ts` covers.
 *
 * `evalConditionGroup`'s tail is deliberate: `{}` means "no conditions", which
 * is unconditionally true, while a group carrying keys we do not recognise (a
 * typo'd `all`, a row from a hand-edited store) reads false, because treating
 * it as "no conditions" would turn a conditional allow into an unconditional
 * one. `traceGroup`'s fallback carried no comment and collapsed both cases to
 * `false`, so `explain()` reported a denial for a rule `can()` allowed.
 *
 * These compare the traced group result against the decision path itself
 * rather than against a hand-written expectation, so the two cannot drift
 * apart again without this failing.
 */
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

/** The top-level group result the trace reports for a rule's conditions. */
function tracedGroupResult(conditions: AccessControl.IConditionGroup): boolean {
  const result = explainEvaluation([policyWith(conditions)], REQUEST, 'deny', subjectInfo, 'and')
  const rule = result.policies[0]?.rules[0]
  if (rule === undefined) throw new Error('trace produced no rule')
  return rule.conditions.result
}

/**
 * A group whose keys the type does not describe. Parsed from JSON rather than
 * written as a literal so it arrives genuinely untyped - which is how a real
 * one arrives, off a store row - instead of being forced past the checker.
 */
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
      expect(tracedGroupResult(group)).toBe(evalConditionGroup(REQUEST, group, 0))
    })
  }

  it('the empty object specifically is true on both paths, not false', () => {
    // Pinned as an absolute, not just as parity: two paths agreeing on the
    // wrong answer would satisfy the comparison above.
    const empty = malformedGroup('{}')
    expect(evalConditionGroup(REQUEST, empty, 0)).toBe(true)
    expect(tracedGroupResult(empty)).toBe(true)
  })

  it('an unrecognised key specifically is false on both paths', () => {
    const bogus = malformedGroup('{"foo":1}')
    expect(evalConditionGroup(REQUEST, bogus, 0)).toBe(false)
    expect(tracedGroupResult(bogus)).toBe(false)
  })
})
