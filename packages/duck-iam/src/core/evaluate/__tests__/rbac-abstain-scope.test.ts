import { describe, expect, it, vi } from 'vitest'
import { IAM_RBAC_POLICY_ID } from '../../rbac'
import type { AccessControl, IamRequest } from '../../types'
import { evaluatePolicy } from '../evaluate'

// `rulesAbstainOnThrow` needs both the `__rbac__` id and no deny rule. A throwing rule in an operator's own policy
// must raise (Indeterminate), since the compiled table treats that policy as one unit.
const REQUEST: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: { ua: 'y' }, id: 'u1', roles: [] },
}

/** Parsed from JSON so the unknown operator arrives untyped, as a store row does. */
function policyFrom(id: string, extraRules = ''): AccessControl.IPolicy {
  return JSON.parse(
    `{"algorithm":"allow-overrides","id":${JSON.stringify(id)},"name":"P","rules":[` +
      `{"actions":["read"],"conditions":{"all":[{"field":"subject.attributes.ua","operator":"bogus","value":"y"}]},` +
      `"effect":"allow","id":"r-throws","priority":10,"resources":["post"]},` +
      `{"actions":["read"],"conditions":{"all":[]},"effect":"allow","id":"r-clean","priority":10,"resources":["post"]}` +
      `${extraRules}]}`,
  )
}

describe('only the generated RBAC union lets a throwing rule abstain', () => {
  it('a throwing rule in the __rbac__ union is skipped, and the clean grant still applies', () => {
    const onRuleError = vi.fn()
    const result = evaluatePolicy(policyFrom(IAM_RBAC_POLICY_ID), REQUEST, 'deny', undefined, onRuleError)
    expect(result.allowed).toBe(true)
    expect(onRuleError).toHaveBeenCalledTimes(1)
  })

  it("an operator's own allow-only policy raises instead of abstaining", () => {
    // The negative half of the gate: without the id check, an unrelated clean rule would decide this policy.
    expect(() => evaluatePolicy(policyFrom('p-operator'), REQUEST, 'deny')).toThrow()
  })

  it('the id is what decides, not the shape - the two policies are otherwise identical', () => {
    // Same rules, same algorithm, same everything but `id`, and opposite
    // outcomes. Nothing else in either policy can account for the difference.
    const rbac = policyFrom(IAM_RBAC_POLICY_ID)
    const mine = policyFrom('p-operator')
    expect(mine.rules).toEqual(rbac.rules)
    expect(mine.algorithm).toBe(rbac.algorithm)
    expect(() => evaluatePolicy(rbac, REQUEST, 'deny')).not.toThrow()
    expect(() => evaluatePolicy(mine, REQUEST, 'deny')).toThrow()
  })

  it('a deny rule anywhere in the union closes the abstention off again', () => {
    // The other half of the gate, kept here so the two are read together.
    const withDeny = policyFrom(
      IAM_RBAC_POLICY_ID,
      ',{"actions":["write"],"conditions":{"all":[]},"effect":"deny","id":"r-deny","priority":1,"resources":["other"]}',
    )
    expect(() => evaluatePolicy(withDeny, REQUEST, 'deny')).toThrow()
  })

  it('a policy with no throwing rule is unaffected by either half', () => {
    const clean: AccessControl.IPolicy = {
      algorithm: 'allow-overrides',
      id: 'p-operator',
      name: 'P',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 10, resources: ['post'] },
      ],
    }
    expect(evaluatePolicy(clean, REQUEST, 'deny').allowed).toBe(true)
  })
})
