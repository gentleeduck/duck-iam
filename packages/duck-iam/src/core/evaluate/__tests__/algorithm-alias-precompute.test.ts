import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'
import { indexPolicy } from '../evaluate.libs'

/**
 * `first-match` and `highest-priority` rank identically - highest priority
 * wins, ties fall to source order - and differ only in the `reason` they
 * report. `highest-priority` was nonetheless left out of the precompute
 * allowlist, so the same policy answered in O(1) under one algorithm name and
 * scanned its rules under the other, with no behavioural reason for the split.
 */
const request: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

const ALGORITHMS: AccessControl.CombiningAlgorithm[] = [
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
]

function policyOf(algorithm: AccessControl.CombiningAlgorithm, rules: AccessControl.IRule[]): AccessControl.IPolicy {
  return { algorithm, id: `p-${algorithm}`, name: 'p', rules }
}

function unconditional(effect: AccessControl.Effect, id: string, priority: number): AccessControl.IRule {
  return { actions: ['read'], conditions: { all: [] }, effect, id, priority, resources: ['post'] }
}

const UNCONDITIONAL: AccessControl.IRule[] = [unconditional('allow', 'r-allow', 5), unconditional('deny', 'r-deny', 1)]

describe('precompute covers every algorithm that can be precomputed', () => {
  it.each(ALGORITHMS)('%s precomputes an unconditional wildcardless policy', (algorithm) => {
    const index = indexPolicy(policyOf(algorithm, UNCONDITIONAL))
    expect(index.precomputed.get('read')?.get('post')).toBeDefined()
  })

  it('and the precomputed answer matches what the interpreter reaches', () => {
    for (const algorithm of ALGORITHMS) {
      const policy = policyOf(algorithm, UNCONDITIONAL)
      const precomputed = indexPolicy(policy).precomputed.get('read')?.get('post')
      expect(precomputed).toBe(evaluate([policy], request, 'deny', 'and').allowed)
      expect(precomputed).toBe(evaluateFast([policy], request, 'deny', 'and'))
    }
  })

  // Control: a wildcard rule can override a literal one, so the table stays
  // empty. Without this the assertions above would pass on a build that
  // precomputed everything unconditionally.
  it('control: a wildcard rule suppresses the table', () => {
    const withWildcard: AccessControl.IRule[] = [
      ...UNCONDITIONAL,
      { actions: ['*'], conditions: { all: [] }, effect: 'deny', id: 'r-star', priority: 9, resources: ['*'] },
    ]
    for (const algorithm of ALGORITHMS) {
      expect(indexPolicy(policyOf(algorithm, withWildcard)).precomputed.size).toBe(0)
    }
  })

  // Control: a conditional rule in the same bucket also suppresses it, since
  // the answer then depends on the request.
  it('control: a conditional rule in the bucket suppresses the table', () => {
    const conditional: AccessControl.IRule[] = [
      ...UNCONDITIONAL,
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
        effect: 'deny',
        id: 'r-cond',
        priority: 9,
        resources: ['post'],
      },
    ]
    for (const algorithm of ALGORITHMS) {
      expect(indexPolicy(policyOf(algorithm, conditional)).precomputed.size).toBe(0)
    }
  })
})

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

describe('first-match and highest-priority are one algorithm', () => {
  it('agree on 3000 generated rule sets, in both engines', () => {
    const rng = mulberry32(0xa11a5)
    for (let i = 0; i < 3000; i++) {
      const count = 1 + Math.floor(rng() * 4)
      const rules: AccessControl.IRule[] = Array.from({ length: count }, (_, r) => {
        const rule = unconditional(rng() < 0.5 ? 'allow' : 'deny', `r${r}`, Math.floor(rng() * 3))
        return { ...rule, actions: [rng() < 0.3 ? '*' : 'read'], resources: [rng() < 0.3 ? '*' : 'post'] }
      })
      const fm = policyOf('first-match', rules)
      const hp = policyOf('highest-priority', rules)
      const slow = evaluate([fm], request, 'deny', 'and').allowed
      if (slow !== evaluate([hp], request, 'deny', 'and').allowed) {
        throw new Error(`Divergence at ${i} (interpreter):\n${JSON.stringify(rules, null, 2)}`)
      }
      if (evaluateFast([fm], request, 'deny', 'and') !== evaluateFast([hp], request, 'deny', 'and')) {
        throw new Error(`Divergence at ${i} (fast path):\n${JSON.stringify(rules, null, 2)}`)
      }
      if (evaluateFast([fm], request, 'deny', 'and') !== slow) {
        throw new Error(`Slow/fast divergence at ${i}:\n${JSON.stringify(rules, null, 2)}`)
      }
    }
  })

  // The two names are kept because the `reason` they report is the useful
  // difference; aliasing them outright would change what an operator reads in
  // an audit log.
  it('differ only in the reason they report', () => {
    expect(evaluate([policyOf('first-match', UNCONDITIONAL)], request, 'deny', 'and').reason).toMatch(/^First match:/)
    expect(evaluate([policyOf('highest-priority', UNCONDITIONAL)], request, 'deny', 'and').reason).toMatch(
      /^Highest priority:/,
    )
  })
})
