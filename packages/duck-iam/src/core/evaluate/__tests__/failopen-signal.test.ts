import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast, type IEvalSignals } from '../evaluate'

/**
 * `SECURITY.md` tells operators to chart `failOpen` to alert on a policy set
 * that has silently stopped denying. The flag only ever fired when *no* policy
 * was applicable, which is the rare shape. The common one - a policy that is
 * applicable, whose every rule evaluated false, so `defaultEffect: 'allow'`
 * supplied the verdict - left it flat at 0. An attribute rename, an adapter
 * returning empty conditions or a condition dropped for being oversized all
 * produce exactly that, and the metric designed to catch it did not move.
 */
type Sig = IEvalSignals

function request(tier: string): IamRequest.IAccessRequest {
  return {
    action: 'read',
    environment: {},
    resource: { attributes: {}, type: 'doc' },
    subject: { attributes: { tier }, id: 'u1', roles: [] },
  }
}

/** One deny rule, shaped for the request, whose condition does not hold. */
function denyBanned(id: string): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    id,
    name: id,
    rules: [
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'banned' }] },
        effect: 'deny',
        id: `${id}-r`,
        priority: 1,
        resources: ['doc'],
      },
    ],
  }
}

/** An explicit allow that no fallback is involved in. */
const allowRule: AccessControl.IPolicy = {
  algorithm: 'first-match',
  id: 'p-allow',
  name: 'allow',
  rules: [
    { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 1, resources: ['doc'] },
  ],
}

/** Not shaped for this request at all: NotApplicable, contributes no vote. */
const unrelated: AccessControl.IPolicy = {
  algorithm: 'first-match',
  id: 'p-unrelated',
  name: 'unrelated',
  rules: [
    { actions: ['write'], conditions: { all: [] }, effect: 'deny', id: 'r-w', priority: 1, resources: ['other'] },
  ],
}

function run(
  policies: AccessControl.IPolicy[],
  defaultEffect: AccessControl.Effect,
  combine: AccessControl.PolicyCombine,
): { slow: { allowed: boolean; failOpen: boolean }; fast: { allowed: boolean; failOpen: boolean } } {
  const slowSignals: Sig = {}
  const allowed = evaluate(policies, request('gold'), defaultEffect, combine, undefined, slowSignals).allowed
  const fastSignals: Sig = {}
  const fast = evaluateFast(policies, request('gold'), defaultEffect, combine, undefined, fastSignals)
  return {
    fast: { allowed: fast, failOpen: fastSignals.failOpen === true },
    slow: { allowed, failOpen: slowSignals.failOpen === true },
  }
}

describe('failOpen on an applicable policy whose rules all evaluated false', () => {
  it.each(['and', 'allow-overrides'] as const)('%s: raised in both engines', (combine) => {
    const { slow, fast } = run([denyBanned('p1')], 'allow', combine)
    expect(slow).toEqual({ allowed: true, failOpen: true })
    expect(fast).toEqual({ allowed: true, failOpen: true })
  })

  it('first-applicable: raised (interpreter only - production blocks this combine)', () => {
    const signals: Sig = {}
    const decision = evaluate([denyBanned('p1')], request('gold'), 'allow', 'first-applicable', undefined, signals)
    expect(decision.allowed).toBe(true)
    expect(signals.failOpen).toBe(true)
  })

  // The decision's own `reason` already said the allow came from the fallback
  // while the flag stayed false. They must not disagree.
  it("agrees with the decision's own reason", () => {
    const signals: Sig = {}
    const decision = evaluate([denyBanned('p1')], request('gold'), 'allow', 'and', undefined, signals)
    expect(decision.reason).toMatch(/No matching rules/i)
    expect(signals.failOpen).toBe(true)
  })
})

describe('failOpen is not raised where the allow is real', () => {
  it.each(['and', 'allow-overrides'] as const)('%s: an explicit allow rule fired', (combine) => {
    const { slow, fast } = run([allowRule], 'allow', combine)
    expect(slow).toEqual({ allowed: true, failOpen: false })
    expect(fast).toEqual({ allowed: true, failOpen: false })
  })

  // A deny verdict is never a fail-open, even though a sibling policy defaulted.
  it('and: the verdict is deny', () => {
    const denyAll: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p-deny',
      name: 'deny',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'r-d', priority: 1, resources: ['doc'] },
      ],
    }
    const { slow, fast } = run([denyBanned('p1'), denyAll], 'allow', 'and')
    expect(slow).toEqual({ allowed: false, failOpen: false })
    expect(fast).toEqual({ allowed: false, failOpen: false })
  })

  // Under allow-overrides the first policy to allow ends the scan, and only
  // that policy's vote carries the verdict. With the explicit allow first the
  // defaulting sibling is never reached and the flag stays down.
  it('allow-overrides: the explicit allow is reached first', () => {
    const { slow, fast } = run([allowRule, denyBanned('p1')], 'allow', 'allow-overrides')
    expect(slow).toEqual({ allowed: true, failOpen: false })
    expect(fast).toEqual({ allowed: true, failOpen: false })
  })

  it('defaultEffect deny never raises it', () => {
    for (const combine of ['and', 'allow-overrides'] as const) {
      const { slow, fast } = run([denyBanned('p1')], 'deny', combine)
      expect(slow.failOpen).toBe(false)
      expect(fast.failOpen).toBe(false)
    }
  })
})

describe('the pre-existing shape still works', () => {
  it('no applicable policy at all', () => {
    const { slow, fast } = run([unrelated], 'allow', 'and')
    expect(slow).toEqual({ allowed: true, failOpen: true })
    expect(fast).toEqual({ allowed: true, failOpen: true })
  })

  it('no policies configured', () => {
    const { slow, fast } = run([], 'allow', 'and')
    expect(slow).toEqual({ allowed: true, failOpen: true })
    expect(fast).toEqual({ allowed: true, failOpen: true })
  })
})

/**
 * The two engines must agree on the flag, not only on the verdict - a metric
 * that moves in development and not in production is worse than no metric.
 */
describe('dev/prod parity of the signal', () => {
  const sets: Array<[string, AccessControl.IPolicy[]]> = [
    ['defaulting only', [denyBanned('p1')]],
    ['defaulting twice', [denyBanned('p1'), denyBanned('p2')]],
    ['defaulting + explicit allow', [denyBanned('p1'), allowRule]],
    ['explicit allow + defaulting', [allowRule, denyBanned('p1')]],
    ['defaulting + unrelated', [denyBanned('p1'), unrelated]],
    ['explicit allow only', [allowRule]],
    ['unrelated only', [unrelated]],
  ]

  for (const [name, policies] of sets) {
    for (const combine of ['and', 'allow-overrides'] as const) {
      for (const defaultEffect of ['allow', 'deny'] as const) {
        it(`${name} / ${combine} / ${defaultEffect}`, () => {
          const { slow, fast } = run(policies, defaultEffect, combine)
          expect(fast).toEqual(slow)
        })
      }
    }
  }
})
