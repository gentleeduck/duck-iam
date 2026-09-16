import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine/engine'
import type { AccessControl, IamRequest } from '../../types'
import { validatePolicy } from '../../validate'
import { evaluate, evaluateFast } from '../evaluate'

// SECURITY: an unrecognised effect (`'DENY'` on an unvalidated row) votes for neither side in the fast path,
// as in the interpreter, which falls through to `defaultEffect`.

/** Malformed: an effect casing no validator would accept. */
const BOGUS_EFFECT = 'DENY' as unknown as AccessControl.Effect

const REQUEST: IamRequest.IAccessRequest = {
  action: 'read',
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u', roles: [] },
}

/** A wildcard resource keeps the policy residual, which is what routes it to `evaluatePolicyFast`. */
function denyOnlyPolicy(
  algorithm: AccessControl.CombiningAlgorithm,
  effect: AccessControl.Effect,
): AccessControl.IPolicy {
  return {
    algorithm,
    id: 'p0',
    name: 'p0',
    rules: [{ actions: ['read'], conditions: { all: [] }, effect, id: 'only', priority: 0, resources: ['*'] }],
  }
}

describe('an unrecognised rule effect votes for neither side', () => {
  it('the write path refuses it, which is why only seeded rows reach the evaluator', () => {
    const issues = validatePolicy(denyOnlyPolicy('deny-overrides', BOGUS_EFFECT)).issues
    expect(issues.map((i) => i.code)).toContain('INVALID_EFFECT')
  })

  it('deny-overrides: a deny-only policy does not become an allow on the fast path', () => {
    expect({
      bogus: evaluateFast([denyOnlyPolicy('deny-overrides', BOGUS_EFFECT)], REQUEST, 'deny'),
      control: evaluateFast([denyOnlyPolicy('deny-overrides', 'deny')], REQUEST, 'deny'),
    }).toEqual({ bogus: false, control: false })
  })

  it('allow-overrides: it does not become a deny-carrying vote either', () => {
    // Mirror image: `allow-overrides` must not read a bogus effect as a deny either.
    expect({
      bogus: evaluateFast([denyOnlyPolicy('allow-overrides', BOGUS_EFFECT)], REQUEST, 'allow'),
      controlAllow: evaluateFast([denyOnlyPolicy('allow-overrides', 'allow')], REQUEST, 'deny'),
      controlDeny: evaluateFast([denyOnlyPolicy('allow-overrides', 'deny')], REQUEST, 'allow'),
    }).toEqual({ bogus: true, controlAllow: true, controlDeny: false })
  })

  it('the fast path agrees with the interpreter on every algorithm', () => {
    const algorithms: AccessControl.CombiningAlgorithm[] = [
      'deny-overrides',
      'allow-overrides',
      'first-match',
      'highest-priority',
    ]
    const disagreements = algorithms.flatMap((algorithm) =>
      (['allow', 'deny'] as const).flatMap((defaultEffect) => {
        const policies = [denyOnlyPolicy(algorithm, BOGUS_EFFECT)]
        const fast = evaluateFast(policies, REQUEST, defaultEffect)
        const slow = evaluate(policies, REQUEST, defaultEffect).allowed
        return fast === slow ? [] : [`${algorithm}/${defaultEffect}: fast=${fast} slow=${slow}`]
      }),
    )
    expect(disagreements).toEqual([])
  })

  it('end-to-end: production does not allow what development denies', async () => {
    const policies = [denyOnlyPolicy('deny-overrides', BOGUS_EFFECT)]
    const production = new IamEngine({ adapter: new IamMemoryAdapter({ policies }), mode: 'production' })
    const development = new IamEngine({ adapter: new IamMemoryAdapter({ policies }), mode: 'development' })
    // `authorize`'s return type is mode-dependent - a bare boolean in
    // production, an IDecision in development - so read `allowed` off each.
    const devResult = await development.authorize(REQUEST)
    const prodResult = await production.authorize(REQUEST)
    expect({
      development: devResult.allowed,
      production: prodResult,
    }).toEqual({ development: false, production: false })
  })
})
