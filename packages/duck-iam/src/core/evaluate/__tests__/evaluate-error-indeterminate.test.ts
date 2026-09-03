import { describe, expect, it, vi } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'

/**
 * An evaluation error is Indeterminate, not NotApplicable. Skipping a policy
 * that throws lets an attacker disable a deny rule by padding the field it
 * matches on (a >2048-char User-Agent makes `matches` throw), after which a
 * sibling allow wins. A policy that could have denied must fail closed.
 */
const OVERSIZED = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')

function request(userAgent: string): IamRequest.IAccessRequest {
  return {
    subject: { id: 'u1', roles: [], attributes: {} },
    action: 'read',
    resource: { type: 'post', attributes: {} },
    environment: { userAgent },
  }
}

const allowAll: AccessControl.IPolicy = {
  id: 'p-allow',
  name: 'allow',
  algorithm: 'first-match',
  rules: [
    { id: 'r-allow', effect: 'allow', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
  ],
}

const denyBots: AccessControl.IPolicy = {
  id: 'p-deny-bots',
  name: 'deny bots',
  algorithm: 'first-match',
  rules: [
    {
      id: 'r-deny',
      effect: 'deny',
      priority: 10,
      actions: ['*'],
      resources: ['*'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
    },
  ],
}

/** Only allow rules: a throw here casts the `defaultEffect` vote, never abstains. */
const allowOnlyThatThrows: AccessControl.IPolicy = {
  id: 'p-allow-throws',
  name: 'allow throws',
  algorithm: 'first-match',
  rules: [
    {
      id: 'r-allow-throws',
      effect: 'allow',
      priority: 5,
      actions: ['*'],
      resources: ['*'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
    },
  ],
}

describe("evaluate ('and') with a throwing deny policy", () => {
  it('denies rather than skipping the deny policy', () => {
    const onPolicyError = vi.fn()
    const decision = evaluate([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', onPolicyError)
    expect(decision.allowed).toBe(false)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  it('control: a normal-length matching user agent also denies', () => {
    expect(evaluate([allowAll, denyBots], request('curl'), 'deny', 'and').allowed).toBe(false)
  })

  // This previously asserted `allowed === true` on the reasoning that an error
  // in an allow-only policy cannot grant anything. It can: the policy's vote,
  // had it evaluated, would have been `defaultEffect` - a deny - and skipping
  // it drops that deny. Padding the user agent past the regex input cap was
  // therefore enough to buy an allow.
  it('an allow-only policy that throws still casts its defaultEffect vote', () => {
    const onPolicyError = vi.fn()
    const decision = evaluate([allowAll, allowOnlyThatThrows], request(OVERSIZED), 'deny', 'and', onPolicyError)
    expect(decision.allowed).toBe(false)
    expect(decision.applicable).not.toBe(false)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  it('control: the same throw under defaultEffect allow votes allow and flags failOpen', () => {
    const signals = { failOpen: false }
    const decision = evaluate([allowAll, allowOnlyThatThrows], request(OVERSIZED), 'allow', 'and', vi.fn(), signals)
    expect(decision.allowed).toBe(true)
    expect(signals.failOpen).toBe(true)
  })
})

describe("evaluateFast ('and') with a throwing deny policy", () => {
  it('denies rather than skipping the deny policy', () => {
    const onPolicyError = vi.fn()
    expect(evaluateFast([allowAll, denyBots], request(OVERSIZED), 'deny', 'and', onPolicyError)).toBe(false)
    expect(onPolicyError).toHaveBeenCalledOnce()
  })

  // Mirrors the slow-path correction above: the fast path had its own copy of
  // the skip, so fixing only one of the two would have left prod and dev
  // disagreeing on exactly this input.
  it('an allow-only policy that throws still casts its defaultEffect vote', () => {
    expect(evaluateFast([allowAll, allowOnlyThatThrows], request(OVERSIZED), 'deny', 'and')).toBe(false)
  })
})

/**
 * With no sibling allow, a throwing deny must not fall through to a
 * `defaultEffect: 'allow'` engine - that is the fail-open the padding buys.
 */
describe.each(['and', 'allow-overrides'] as const)('fail-open engine (%s), lone throwing deny', (combine) => {
  it('evaluate denies', () => {
    expect(evaluate([denyBots], request(OVERSIZED), 'allow', combine).allowed).toBe(false)
  })

  it('evaluateFast denies', () => {
    expect(evaluateFast([denyBots], request(OVERSIZED), 'allow', combine)).toBe(false)
  })

  it('control: an allow-only throwing policy still defaults to allow', () => {
    expect(evaluate([allowOnlyThatThrows], request(OVERSIZED), 'allow', combine).allowed).toBe(true)
  })
})

/**
 * The fast path can reach a verdict without ever evaluating the throwing rule -
 * `allow-overrides` returns on its first unconditional allow, and the
 * precomputed map answers before any condition runs - so production allowed
 * what development denied. A 10k-case throw-injection fuzz showed 71 such
 * divergences, every one of them prod-allows/dev-denies.
 */
const allowThenThrowingDeny: AccessControl.IPolicy = {
  id: 'p-early-return',
  name: 'early return',
  algorithm: 'allow-overrides',
  rules: [
    { id: 'r-allow', effect: 'allow', priority: 2, actions: ['read'], resources: ['post'], conditions: { all: [] } },
    {
      id: 'r-deny-throws',
      effect: 'deny',
      priority: 2,
      actions: ['read'],
      resources: ['*'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
    },
  ],
}

describe('a throwing rule the fast path would skip past', () => {
  it('makes both engines agree, rather than only the one that reached the rule', () => {
    const slow = evaluate([allowThenThrowingDeny], request(OVERSIZED), 'deny', 'and', vi.fn()).allowed
    const fast = evaluateFast([allowThenThrowingDeny], request(OVERSIZED), 'deny', 'and', vi.fn())
    expect(fast).toBe(slow)
    expect(fast).toBe(false)
  })

  // Control: without the oversized input nothing throws, the deny's condition
  // is simply false, and both engines allow. If this went red the test above
  // would be passing only because everything denies.
  it('still allows both ways on a normal-length user agent', () => {
    expect(evaluate([allowThenThrowingDeny], request('firefox'), 'deny', 'and').allowed).toBe(true)
    expect(evaluateFast([allowThenThrowingDeny], request('firefox'), 'deny', 'and')).toBe(true)
  })

  // The precomputed map is the other way the fast path answers without running
  // any condition. This shape agreed even before the fix - the throwing rule is
  // on a cell the request never touches - so it is a control on the delegation
  // not changing a verdict that was already correct.
  it('agrees on a precomputed cell whose sibling rule throws', () => {
    const policy: AccessControl.IPolicy = {
      id: 'p-precomputed',
      name: 'precomputed',
      algorithm: 'deny-overrides',
      rules: [
        { id: 'r-a', effect: 'allow', priority: 1, actions: ['read'], resources: ['post'], conditions: { all: [] } },
        {
          id: 'r-d',
          effect: 'deny',
          priority: 1,
          actions: ['read'],
          resources: ['comment'],
          conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
        },
      ],
    }
    const slow = evaluate([policy], request(OVERSIZED), 'deny', 'and', vi.fn()).allowed
    expect(evaluateFast([policy], request(OVERSIZED), 'deny', 'and', vi.fn())).toBe(slow)
  })
})
