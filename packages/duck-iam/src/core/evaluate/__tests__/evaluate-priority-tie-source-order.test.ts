import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluatePolicy, evaluatePolicyFast } from '../evaluate'

/**
 * `first-match` and `highest-priority` both resolve equal priorities by source
 * order. The interpreter walks `policy.rules` directly, but `evaluatePolicyFast`
 * walks the rule index, which groups literal-resource rules into one bucket and
 * wildcard-resource rules into another and visits the literal bucket first.
 *
 * A deny declared first with an expansive resource therefore lost a priority tie
 * to an allow declared second with a literal resource: development denied and
 * production allowed the same request. These cases pin the two paths together.
 */

const request: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, id: 'p1', type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

function rule(
  id: string,
  effect: AccessControl.Effect,
  resources: string[],
  priority: number,
): AccessControl.IRule<string, string> {
  return { actions: ['read'], conditions: { all: [] }, effect, id, priority, resources }
}

function policy(algorithm: AccessControl.CombiningAlgorithm, rules: AccessControl.IRule[]): AccessControl.IPolicy {
  return { algorithm, id: 'p', name: 'p', rules }
}

const TIE_BREAKING: AccessControl.CombiningAlgorithm[] = ['first-match', 'highest-priority']

describe('priority ties resolve by source order on both evaluation paths', () => {
  for (const algorithm of TIE_BREAKING) {
    it(`${algorithm}: a wildcard deny declared before a literal allow wins the tie`, () => {
      const p = policy(algorithm, [rule('deny-all', 'deny', ['*'], 10), rule('allow-post', 'allow', ['post'], 10)])

      const dev = evaluatePolicy(p, request)
      expect(dev.applicable).not.toBe(false)
      expect(dev.allowed).toBe(false)
      expect(evaluatePolicyFast(p, request)).toBe(false)
    })

    it(`${algorithm}: a literal allow declared before a wildcard deny wins the tie`, () => {
      const p = policy(algorithm, [rule('allow-post', 'allow', ['post'], 10), rule('deny-all', 'deny', ['*'], 10)])

      const dev = evaluatePolicy(p, request)
      expect(dev.allowed).toBe(true)
      expect(evaluatePolicyFast(p, request)).toBe(true)
    })

    it(`${algorithm}: a strictly higher priority still beats source order`, () => {
      const p = policy(algorithm, [rule('deny-all', 'deny', ['*'], 10), rule('allow-post', 'allow', ['post'], 11)])

      const dev = evaluatePolicy(p, request)
      expect(dev.allowed).toBe(true)
      expect(evaluatePolicyFast(p, request)).toBe(true)
    })

    it(`${algorithm}: hierarchical wildcard deny ties are also source-ordered`, () => {
      const nested: IamRequest.IAccessRequest = {
        ...request,
        resource: { attributes: {}, id: 'u1', type: 'dashboard.users' },
      }
      const p = policy(algorithm, [
        rule('deny-tree', 'deny', ['dashboard.*'], 3),
        rule('allow-leaf', 'allow', ['dashboard.users'], 3),
      ])

      expect(evaluatePolicy(p, nested).allowed).toBe(false)
      expect(evaluatePolicyFast(p, nested)).toBe(false)
    })
  }

  it('deny-overrides and allow-overrides stay order independent', () => {
    const rules = [rule('deny-all', 'deny', ['*'], 10), rule('allow-post', 'allow', ['post'], 10)]
    const reversed = [rules[1]!, rules[0]!]

    for (const algorithm of ['deny-overrides', 'allow-overrides'] as const) {
      const forward = policy(algorithm, rules)
      const backward = policy(algorithm, reversed)
      const expected = algorithm === 'deny-overrides' ? false : true

      expect(evaluatePolicy(forward, request).allowed).toBe(expected)
      expect(evaluatePolicy(backward, request).allowed).toBe(expected)
      expect(evaluatePolicyFast(forward, request)).toBe(expected)
      expect(evaluatePolicyFast(backward, request)).toBe(expected)
    }
  })
})
