import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'

/**
 * `evaluate-priority-tie-source-order.test.ts` covers four hand-written
 * orderings. The tie-break is the one place the interpreter's linear scan and
 * the fast path's bucket walk can disagree by construction - the fast path
 * visits literal buckets before wildcard ones, so bucket order is not source
 * order - and four orderings is not a sample.
 *
 * Two separate claims live here. The parity one is a guarantee: for any given
 * order, both engines return the same verdict. The order-dependence one is not
 * a bug but a documented consequence of source order being the tie-break, and
 * it is asserted so the suite says out loud that a policy with equal-priority
 * opposing rules is only as deterministic as the adapter's row order.
 */
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

const ACTIONS = ['read', 'write']
const RESOURCES = ['post', 'comment']
/** Mixed literal and expansive, so the fast path splits the rules across buckets. */
const PATTERNS = ['read', 'write', '*', 'posts:*']
const TIE_ALGORITHMS: AccessControl.CombiningAlgorithm[] = ['first-match', 'highest-priority']

const request: IamRequest.IAccessRequest = {
  action: 'read',
  environment: {},
  resource: { attributes: {}, type: 'post' },
  subject: { attributes: {}, id: 'u1', roles: [] },
}

function makeRules(rng: () => number): AccessControl.IRule[] {
  const count = 2 + Math.floor(rng() * 3)
  return Array.from({ length: count }, (_, i) => ({
    // Two priority values across up to four rules, so ties are the common case.
    actions: [
      rng() < 0.4 ? (PATTERNS[Math.floor(rng() * PATTERNS.length)] ?? '*') : (ACTIONS[Math.floor(rng() * 2)] ?? 'read'),
    ],
    conditions: { all: [] },
    effect: rng() < 0.5 ? 'allow' : 'deny',
    id: `r${i}`,
    priority: Math.floor(rng() * 2),
    resources: [rng() < 0.3 ? '*' : (RESOURCES[Math.floor(rng() * 2)] ?? 'post')],
  }))
}

function shuffled<T>(rng: () => number, xs: readonly T[]): T[] {
  const out = [...xs]
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1))
    const a = out[i]
    const b = out[j]
    if (a !== undefined && b !== undefined) {
      out[i] = b
      out[j] = a
    }
  }
  return out
}

describe('equal-priority tie-break under shuffled rule order', () => {
  const MULTISETS = 2000
  const SHUFFLES = 6

  it('both engines agree on every shuffle of every multiset', () => {
    const rng = mulberry32(0x71e17ea1)
    let checked = 0
    for (let i = 0; i < MULTISETS; i++) {
      const rules = makeRules(rng)
      const algorithm = TIE_ALGORITHMS[i % TIE_ALGORITHMS.length] ?? 'first-match'
      for (let s = 0; s < SHUFFLES; s++) {
        const policy: AccessControl.IPolicy = {
          algorithm,
          id: `p${i}-${s}`,
          name: 'p',
          rules: shuffled(rng, rules),
        }
        const slow = evaluate([policy], request, 'deny', 'and').allowed
        const fast = evaluateFast([policy], request, 'deny', 'and')
        checked++
        if (slow !== fast) {
          throw new Error(
            `Divergence at multiset ${i} shuffle ${s}: evaluate=${slow} evaluateFast=${fast}\n${JSON.stringify(policy, null, 2)}`,
          )
        }
      }
    }
    expect(checked).toBe(MULTISETS * SHUFFLES)
  })

  it('and the verdict does depend on the order, which is the documented contract', () => {
    const rng = mulberry32(0x71e17ea1)
    let orderDependent = 0
    for (let i = 0; i < MULTISETS; i++) {
      const rules = makeRules(rng)
      const algorithm = TIE_ALGORITHMS[i % TIE_ALGORITHMS.length] ?? 'first-match'
      const verdicts = new Set<boolean>()
      for (let s = 0; s < SHUFFLES; s++) {
        const policy: AccessControl.IPolicy = {
          algorithm,
          id: `p${i}-${s}`,
          name: 'p',
          rules: shuffled(rng, rules),
        }
        verdicts.add(evaluate([policy], request, 'deny', 'and').allowed)
      }
      if (verdicts.size > 1) orderDependent++
    }
    // Not an assertion about the exact count - only that the phenomenon the
    // first test guards parity over is real and common, so parity is not
    // holding trivially because every shuffle produces the same verdict.
    expect(orderDependent).toBeGreaterThan(MULTISETS / 20)
  })

  // Control: distinct priorities remove the ambiguity entirely, which is the
  // remedy the type's doc points authors at.
  it('control: distinct priorities make the verdict order-independent', () => {
    const rules: AccessControl.IRule[] = [
      { actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'r-deny', priority: 20, resources: ['post'] },
      { actions: ['*'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 1, resources: ['*'] },
    ]
    const rng = mulberry32(7)
    for (let s = 0; s < 20; s++) {
      const policy: AccessControl.IPolicy = {
        algorithm: 'first-match',
        id: 'p',
        name: 'p',
        rules: shuffled(rng, rules),
      }
      expect(evaluate([policy], request, 'deny', 'and').allowed).toBe(false)
      expect(evaluateFast([policy], request, 'deny', 'and')).toBe(false)
    }
  })
})
