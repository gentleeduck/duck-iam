import { describe, expect, it } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluatePolicy, evaluatePolicyFast } from '../evaluate'
import { indexPolicy } from '../evaluate.libs'

// Pins the `idx.mayThrow` delegation in `evaluatePolicyFast`, which the oracle cannot see (it compares the interpreter
// with itself there). Only `allow-overrides` fails without it today; the others guard future short-circuits.
const OVERSIZED = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')

function request(userAgent: string): IamRequest.IAccessRequest {
  return {
    action: 'read',
    environment: { userAgent },
    resource: { attributes: {}, type: 'post' },
    subject: { attributes: { level: 3 }, id: 'u1', roles: [] },
  }
}

/** A rule whose `matches` throws when the user agent is oversized. */
function throwingRule(id: string, effect: AccessControl.Effect): AccessControl.IRule {
  return {
    actions: ['read'],
    conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
    effect,
    id,
    priority: 1,
    resources: ['post'],
  }
}

/** An unconditional rule - the one the fast path can answer from its precomputed map. */
function plainRule(id: string, effect: AccessControl.Effect): AccessControl.IRule {
  return { actions: ['read'], conditions: { all: [] }, effect, id, priority: 1, resources: ['post'] }
}

const CASES: { name: string; policy: AccessControl.IPolicy }[] = [
  {
    name: 'allow-overrides returns on its first unconditional allow',
    policy: {
      algorithm: 'allow-overrides',
      id: 'p-allow-first',
      name: 'p',
      rules: [plainRule('r-ok', 'allow'), throwingRule('r-boom', 'deny')],
    },
  },
  {
    name: 'deny-overrides finds no deny among the rules it evaluates',
    policy: {
      algorithm: 'deny-overrides',
      id: 'p-deny-scan',
      name: 'p',
      rules: [plainRule('r-ok', 'allow'), throwingRule('r-boom', 'allow')],
    },
  },
  {
    name: 'first-match takes the first rule and stops',
    policy: {
      algorithm: 'first-match',
      id: 'p-first',
      name: 'p',
      rules: [plainRule('r-ok', 'allow'), throwingRule('r-boom', 'deny')],
    },
  },
  {
    name: 'highest-priority is decided by a rule that does not throw',
    policy: {
      algorithm: 'highest-priority',
      id: 'p-prio',
      name: 'p',
      rules: [
        { ...plainRule('r-ok', 'allow'), priority: 10 },
        { ...throwingRule('r-boom', 'deny'), priority: 1 },
      ],
    },
  },
]

describe('a policy that can throw is decided by the interpreter, whatever the fast path would have said', () => {
  it.each(CASES)('$name', ({ policy }) => {
    // The premise: this policy really is one the delegation applies to. Without
    // it the case could pass because nothing throws at all.
    expect(indexPolicy(policy).mayThrow, 'this policy is not throwable - the case proves nothing').toBe(true)

    const req = request(OVERSIZED)
    // Nothing absorbs the throw at this level, so agreeing means the fast path raises where the interpreter does.
    expect(() => evaluatePolicy(policy, req, 'deny'), 'the interpreter did not throw - premise gone').toThrow()
    expect(
      () => evaluatePolicyFast(policy, req, 'deny'),
      'the fast path answered where the interpreter threw',
    ).toThrow()

    // And the verdict a request actually gets: Indeterminate casts `defaultEffect`, which is deny.
    expect(evaluate([policy], req, 'deny').allowed, 'an unevaluable policy must not allow').toBe(false)
  })

  it('the same policies allow when nothing throws - the deny above is the throw, not the shape', () => {
    // Control: a fast path that always answered `false` would pass the assertions above and fail here.
    const req = request('curl/8.0')
    for (const { policy } of CASES) {
      expect(evaluatePolicy(policy, req, 'deny').allowed, `${policy.id} interpreter`).toBe(true)
      expect(evaluatePolicyFast(policy, req, 'deny'), `${policy.id} fast path`).toBe(true)
    }
  })

  it('a policy with no throwable condition still takes the fast path', () => {
    // PERF: the delegation must stay narrow, or every policy pays the interpreter's price.
    const policy: AccessControl.IPolicy = {
      algorithm: 'allow-overrides',
      id: 'p-plain',
      name: 'p',
      rules: [plainRule('r-ok', 'allow')],
    }
    expect(indexPolicy(policy).mayThrow).toBe(false)
    expect(evaluatePolicyFast(policy, request('curl/8.0'), 'deny')).toBe(true)
  })
})
