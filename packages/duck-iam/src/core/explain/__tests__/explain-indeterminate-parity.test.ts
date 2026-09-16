import { describe, expect, it } from 'vitest'
import { iamEvaluate } from '../..'
import type { AccessControl, IamRequest } from '../../types'
import { explainEvaluation } from '../explain'
import type { Explain } from '../explain.types'

// `evaluate` absorbs a throwing rule as Indeterminate: deny if the policy carries any deny rule, else `defaultEffect`.
// `explain()` must do the same rather than raise on the very inputs it is opened to explain.
const REQUEST: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: { path: 'x' }, type: 'post' },
  subject: { attributes: { ua: 'y' }, id: 'u1', roles: [] },
}

const subjectInfo: Explain.ISubjectInfo = { originalRoles: [], scopedRolesApplied: [], subjectId: 'u1' }

/** Built through JSON so the malformed shapes arrive untyped, the way a store row does. */
function policyFrom(json: string): AccessControl.IPolicy {
  return JSON.parse(json)
}

/** Each throws inside `ruleApplies`; `evaluate` absorbs all three. */
const THROWING_CONDITIONS: readonly [string, string][] = [
  ['an unknown operator', '{"all":[{"field":"subject.attributes.ua","operator":"bogus","value":"y"}]}'],
  ['a null all-group', '{"all":null}'],
  ['a non-array all-group', '{"all":"nope"}'],
]

function policyWith(conditions: string, withDenyRule: boolean): AccessControl.IPolicy {
  const deny = withDenyRule
    ? ',{"actions":["read"],"conditions":{"all":[]},"effect":"deny","id":"r2","priority":1,"resources":["other"]}'
    : ''
  return policyFrom(
    `{"algorithm":"deny-overrides","id":"p1","name":"P","rules":[` +
      `{"actions":["read"],"conditions":${conditions},"effect":"allow","id":"r1","priority":1,"resources":["post"]}` +
      `${deny}]}`,
  )
}

describe('explain() absorbs a throwing rule exactly as the decision path does', () => {
  for (const [name, conditions] of THROWING_CONDITIONS) {
    for (const withDenyRule of [false, true]) {
      for (const defaultEffect of ['deny', 'allow'] as const) {
        const label = `${name}${withDenyRule ? ' + a deny rule' : ''} under defaultEffect "${defaultEffect}"`

        it(`${label}: explain does not throw`, () => {
          const policy = policyWith(conditions, withDenyRule)
          expect(() => explainEvaluation([policy], REQUEST, defaultEffect, subjectInfo, 'and')).not.toThrow()
        })

        it(`${label}: explain agrees with evaluate`, () => {
          const policy = policyWith(conditions, withDenyRule)
          const expected = iamEvaluate([policy], REQUEST, defaultEffect, 'and', undefined, undefined, undefined, true)
          const traced = explainEvaluation([policy], REQUEST, defaultEffect, subjectInfo, 'and')
          expect(traced.decision.allowed).toBe(expected.allowed)
        })
      }
    }

    it(`${name}: the failure is recorded in the trace, not swallowed`, () => {
      // Absorbing the throw must not make it invisible; a silent `false` is worse than a crash.
      const traced = explainEvaluation([policyWith(conditions, false)], REQUEST, 'deny', subjectInfo, 'and')
      const rule = traced.policies[0]?.rules[0]
      if (rule === undefined) throw new Error('trace produced no rule')
      expect(rule.conditionError).toBeTypeOf('string')
      expect(rule.conditionsMet).toBe(false)
      expect(rule.matched).toBe(false)
    })
  }

  it('a well-formed policy still carries no error and is unaffected', () => {
    const policy = policyWith('{"all":[{"field":"subject.attributes.ua","operator":"eq","value":"y"}]}', false)
    const traced = explainEvaluation([policy], REQUEST, 'deny', subjectInfo, 'and')
    const rule = traced.policies[0]?.rules[0]
    if (rule === undefined) throw new Error('trace produced no rule')
    expect(rule.conditionError).toBeUndefined()
    expect(rule.matched).toBe(true)
    expect(traced.decision.allowed).toBe(true)
  })
})
