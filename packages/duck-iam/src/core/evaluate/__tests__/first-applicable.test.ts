import { describe, expect, it, vi } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate } from '../evaluate'

// `first-applicable` returns the first result that is not NotApplicable, including votes that name no rule:
// a condition-false policy's `defaultEffect`, and a throwing policy's Indeterminate deny.
function request(userAgent = 'firefox'): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: [], attributes: { status: 'suspended' } },
    action: 'delete',
    resource: { type: 'org', attributes: { ownerId: 'other' } },
    environment: { userAgent },
  }
}

/** Applicable - its rule is shaped for the request - but the condition is false. */
const conditionFalse: AccessControl.IPolicy = {
  id: 'p-condition-false',
  name: 'condition false',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r-deny',
      effect: 'deny',
      priority: 0,
      actions: ['*'],
      resources: ['org'],
      conditions: { all: [{ field: 'subject.attributes.status', operator: 'eq', value: 'pending' }] },
    },
  ],
}

const allowAll: AccessControl.IPolicy = {
  id: 'p-allow',
  name: 'allow',
  algorithm: 'first-match',
  rules: [
    { id: 'r-allow', effect: 'allow', priority: -1, actions: ['*'], resources: ['org'], conditions: { all: [] } },
  ],
}

/** Throws on an oversized field, so `safeEval` synthesizes a rule-less deny. */
const denyThrows: AccessControl.IPolicy = {
  id: 'p-deny-throws',
  name: 'deny throws',
  algorithm: 'first-match',
  rules: [
    {
      id: 'r-deny-throws',
      effect: 'deny',
      priority: 10,
      actions: ['*'],
      resources: ['*'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
    },
  ],
}

/** NotApplicable: no rule of this policy is shaped for `delete` on `org`. */
const otherAction: AccessControl.IPolicy = {
  id: 'p-other',
  name: 'other action',
  algorithm: 'first-match',
  rules: [
    { id: 'r-w', effect: 'allow', priority: 1, actions: ['write'], resources: ['post'], conditions: { all: [] } },
  ],
}

const OVERSIZED = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')

describe('first-applicable: an applicable policy that votes its default', () => {
  it('wins over a later allow, matching what `and` decides on the same set', () => {
    const first = evaluate([conditionFalse, allowAll], request(), 'deny', 'first-applicable')
    expect(first.allowed).toBe(false)
    expect(first.policy).toBe('p-condition-false')
    expect(evaluate([conditionFalse, allowAll], request(), 'deny', 'and').allowed).toBe(false)
  })

  // Without this, an implementation that simply denied whenever no rule fired would pass.
  it('votes allow under `defaultEffect: allow`', () => {
    expect(evaluate([conditionFalse], request(), 'allow', 'first-applicable').allowed).toBe(true)
  })
})

describe('first-applicable: the synthesized Indeterminate deny', () => {
  it('is returned rather than skipped, so padding a header cannot buy an allow', () => {
    const onPolicyError = vi.fn()
    const decision = evaluate([denyThrows, allowAll], request(OVERSIZED), 'deny', 'first-applicable', onPolicyError)
    expect(decision.allowed).toBe(false)
    expect(decision.reason).toMatch(/indeterminate/)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  // Neither path relies on the throw: the condition is merely false, or with a matching agent the rule fires.
  it('control: the same set denies on a normal user agent too', () => {
    expect(evaluate([denyThrows, allowAll], request('firefox'), 'deny', 'first-applicable').allowed).toBe(false)
    expect(evaluate([denyThrows, allowAll], request('curl'), 'deny', 'first-applicable').allowed).toBe(false)
  })
})

describe('first-applicable: NotApplicable policies are still skipped', () => {
  it('passes over a policy with no rule for this action/resource', () => {
    const decision = evaluate([otherAction, allowAll], request(), 'deny', 'first-applicable')
    expect(decision.allowed).toBe(true)
    expect(decision.policy).toBe('p-allow')
  })

  it('falls through to the default when every policy is NotApplicable', () => {
    expect(evaluate([otherAction], request(), 'deny', 'first-applicable').allowed).toBe(false)
    expect(evaluate([otherAction], request(), 'allow', 'first-applicable').allowed).toBe(true)
  })

  it('is order-sensitive', () => {
    expect(evaluate([allowAll, conditionFalse], request(), 'deny', 'first-applicable').allowed).toBe(true)
    expect(evaluate([conditionFalse, allowAll], request(), 'deny', 'first-applicable').allowed).toBe(false)
  })
})
