import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { compileTable } from '../../engine/compiled/compiled.compile'
import { lookup } from '../../engine/compiled/compiled.lookup'
import { IamEngine } from '../../engine/engine'
import type { AccessControl, IamRequest } from '../../types'
import { validatePolicy } from '../../validate'
import { evaluate, evaluateFast } from '../evaluate'
import { policyHasDenyRule } from '../evaluate.libs'

/** Malformed: an effect casing no validator would accept. */
const BOGUS_EFFECT = 'DENY' as unknown as AccessControl.Effect

const REQUEST: IamRequest.IAccessRequest = {
  action: 'read',
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u', roles: [] },
}

const rule = (id: string, effect: AccessControl.Effect, resources: string[]): AccessControl.IRule => ({
  actions: ['read'],
  conditions: { all: [] },
  effect,
  id,
  priority: 0,
  resources,
})

/** A wildcard resource keeps the policy residual, which is what routes it to `evaluatePolicyFast`. */
function denyOnlyPolicy(
  algorithm: AccessControl.CombiningAlgorithm,
  effect: AccessControl.Effect,
): AccessControl.IPolicy {
  return { algorithm, id: 'p0', name: 'p0', rules: [rule('only', effect, ['*'])] }
}

/** The shape a deny-only policy cannot show: the deny has a sibling allow to lose to. */
function mixedPolicy(algorithm: AccessControl.CombiningAlgorithm, effect: AccessControl.Effect): AccessControl.IPolicy {
  return { algorithm, id: 'p1', name: 'p1', rules: [rule('allow', 'allow', ['*']), rule('other', effect, ['*'])] }
}

describe('an unrecognised rule effect is Indeterminate, never an abstention', () => {
  it('the write path refuses it, which is why only seeded rows reach the evaluator', () => {
    const issues = validatePolicy(denyOnlyPolicy('deny-overrides', BOGUS_EFFECT)).issues
    expect(issues.map((i) => i.code)).toContain('INVALID_EFFECT')
  })

  it('CONTROL: the sibling allow is what a correctly spelled deny has to beat', () => {
    expect({
      allowAlone: evaluateFast(
        [{ ...mixedPolicy('deny-overrides', 'allow'), rules: [rule('allow', 'allow', ['*'])] }],
        REQUEST,
        'deny',
      ),
      withDeny: evaluateFast([mixedPolicy('deny-overrides', 'deny')], REQUEST, 'deny'),
    }).toEqual({ allowAlone: true, withDeny: false })
  })

  it('a mistyped deny no longer lets its sibling allow through', () => {
    expect({
      fast: evaluateFast([mixedPolicy('deny-overrides', BOGUS_EFFECT)], REQUEST, 'deny'),
      slow: evaluate([mixedPolicy('deny-overrides', BOGUS_EFFECT)], REQUEST, 'deny').allowed,
    }).toEqual({ fast: false, slow: false })
  })

  it('deny-overrides: a deny-only policy does not become an allow on the fast path', () => {
    expect({
      bogus: evaluateFast([denyOnlyPolicy('deny-overrides', BOGUS_EFFECT)], REQUEST, 'deny'),
      control: evaluateFast([denyOnlyPolicy('deny-overrides', 'deny')], REQUEST, 'deny'),
    }).toEqual({ bogus: false, control: false })
  })

  // This case used to expect `bogus: true`, on the reasoning that a bogus effect must not be read as a deny
  // either. It reads as one now: `'DENY'` plainly means a deny, and casting `defaultEffect: 'allow'` for it is
  // the fail-open half of the same coin.
  it('allow-overrides: a bogus effect denies rather than casting `defaultEffect: allow`', () => {
    expect({
      bogus: evaluateFast([denyOnlyPolicy('allow-overrides', BOGUS_EFFECT)], REQUEST, 'allow'),
      controlAllow: evaluateFast([denyOnlyPolicy('allow-overrides', 'allow')], REQUEST, 'deny'),
      controlDeny: evaluateFast([denyOnlyPolicy('allow-overrides', 'deny')], REQUEST, 'allow'),
    }).toEqual({ bogus: false, controlAllow: true, controlDeny: false })
  })

  it('the fast path agrees with the interpreter on every algorithm, in both shapes', () => {
    const algorithms: AccessControl.CombiningAlgorithm[] = [
      'deny-overrides',
      'allow-overrides',
      'first-match',
      'highest-priority',
    ]
    const disagreements = algorithms.flatMap((algorithm) =>
      (['allow', 'deny'] as const).flatMap((defaultEffect) =>
        [denyOnlyPolicy(algorithm, BOGUS_EFFECT), mixedPolicy(algorithm, BOGUS_EFFECT)].flatMap((policy) => {
          const fast = evaluateFast([policy], REQUEST, defaultEffect)
          const slow = evaluate([policy], REQUEST, defaultEffect).allowed
          return fast === slow ? [] : [`${algorithm}/${defaultEffect}/${policy.id}: fast=${fast} slow=${slow}`]
        }),
      ),
    )
    expect(disagreements).toEqual([])
  })

  it('never allows, under any algorithm or default, in either shape', () => {
    const algorithms: AccessControl.CombiningAlgorithm[] = [
      'deny-overrides',
      'allow-overrides',
      'first-match',
      'highest-priority',
    ]
    const allowed = algorithms.flatMap((algorithm) =>
      (['allow', 'deny'] as const).flatMap((defaultEffect) =>
        [denyOnlyPolicy(algorithm, BOGUS_EFFECT), mixedPolicy(algorithm, BOGUS_EFFECT)]
          .filter((policy) => evaluateFast([policy], REQUEST, defaultEffect))
          .map((policy) => `${algorithm}/${defaultEffect}/${policy.id}`),
      ),
    )
    expect(allowed).toEqual([])
  })

  it('counts as a deny rule, so an Indeterminate policy fails closed', () => {
    expect(policyHasDenyRule(denyOnlyPolicy('deny-overrides', BOGUS_EFFECT))).toBe(true)
    expect(policyHasDenyRule(denyOnlyPolicy('deny-overrides', 'allow'))).toBe(false)
  })

  // Measured with the residual check disabled: `lookup()` answers `true` for `'DENY'` and `false` for `'deny'`.
  // The flat model reads a non-allow effect as a deny, but the DYNAMIC cell it lands in asks the combiners, which
  // read it as neither, so the sibling allow wins.
  it('the compiled table would allow it, which is why the policy is kept out', () => {
    const literal = (effect: AccessControl.Effect) => ({
      algorithm: 'deny-overrides' as const,
      id: 'p2',
      name: 'p2',
      rules: [rule('allow', 'allow', ['post']), rule('other', effect, ['post'])],
    })
    const bogus = compileTable([], [literal(BOGUS_EFFECT)], 'and')
    const control = compileTable([], [literal('deny')], 'and')
    const req = { ...REQUEST, resource: { attributes: {}, type: 'post' } }
    expect({
      bogus: lookup(bogus, 0, 'read', 'post', req, 'deny'),
      control: lookup(control, 0, 'read', 'post', req, 'deny'),
    }).toEqual({ bogus: false, control: false })
  })

  it('keeps the policy out of the compiled table, where the flat model would read it as a deny', () => {
    const literal = (effect: AccessControl.Effect) => ({
      algorithm: 'deny-overrides' as const,
      id: 'p2',
      name: 'p2',
      rules: [rule('allow', 'allow', ['post']), rule('other', effect, ['post'])],
    })
    expect(compileTable([], [literal(BOGUS_EFFECT)], 'and').residualPolicies.map((p) => p.id)).toEqual(['p2'])
    expect(compileTable([], [literal('deny')], 'and').residualPolicies).toEqual([])
  })

  it('reports the row through onPolicyError, naming the rule', async () => {
    const seen: string[] = []
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter({ policies: [mixedPolicy('deny-overrides', BOGUS_EFFECT)] }),
      hooks: { onPolicyError: (err) => seen.push(err.message) },
      mode: 'production',
    })
    expect(await engine.authorize(REQUEST)).toBe(false)
    expect(seen.join(' | ')).toMatch(/Unknown effect "DENY" on rule "other"/)
  })

  it('end-to-end: production does not allow what development denies', async () => {
    for (const policies of [
      [denyOnlyPolicy('deny-overrides', BOGUS_EFFECT)],
      [mixedPolicy('deny-overrides', BOGUS_EFFECT)],
    ]) {
      const production = new IamEngine({ adapter: new IamMemoryAdapter({ policies }), mode: 'production' })
      const development = new IamEngine({ adapter: new IamMemoryAdapter({ policies }), mode: 'development' })
      expect({
        development: (await development.authorize(REQUEST)).allowed,
        production: await production.authorize(REQUEST),
      }).toEqual({ development: false, production: false })
    }
  })
})
