import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluatePolicy, evaluatePolicyFast } from '../evaluate'

/**
 * The interpreter and the fast path must agree when two matched rules share a
 * priority. The fast path walks literal buckets before wildcard ones, which is
 * not source order, so a tie is exactly where the two can drift apart.
 */
const ALGORITHMS: AccessControl.CombiningAlgorithm[] = [
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
]

const request: IamRequest.IAccessRequest = {
  subject: { id: 'u1', roles: [], attributes: {} },
  action: 'read',
  resource: { type: 'post', attributes: {} },
  environment: {},
}

type RuleSpec = { id: string; effect: AccessControl.Effect; priority: number; action: string; resource: string }

function policyOf(algorithm: AccessControl.CombiningAlgorithm, specs: RuleSpec[]): AccessControl.IPolicy {
  return {
    id: 'p',
    name: 'p',
    algorithm,
    rules: specs.map((s) => ({
      id: s.id,
      effect: s.effect,
      priority: s.priority,
      actions: [s.action],
      resources: [s.resource],
      conditions: { all: [] },
    })),
  }
}

// Wildcard rule first in source order, literal rule second: the fast path
// visits them in the opposite order.
const ORDERINGS: RuleSpec[][] = [
  [
    { action: '*', effect: 'deny', id: 'wild-deny', priority: 5, resource: 'post' },
    { action: 'read', effect: 'allow', id: 'lit-allow', priority: 5, resource: 'post' },
  ],
  [
    { action: '*', effect: 'allow', id: 'wild-allow', priority: 5, resource: 'post' },
    { action: 'read', effect: 'deny', id: 'lit-deny', priority: 5, resource: 'post' },
  ],
  [
    { action: 'read', effect: 'allow', id: 'lit-allow', priority: 5, resource: 'post' },
    { action: '*', effect: 'deny', id: 'wild-deny', priority: 5, resource: 'post' },
  ],
  [
    { action: 'read', effect: 'deny', id: 'lit-deny', priority: 1, resource: 'post' },
    { action: 'read', effect: 'allow', id: 'lit-allow', priority: 99, resource: 'post' },
  ],
]

describe('priority ties resolve identically in the interpreter and the fast path', () => {
  for (const algorithm of ALGORITHMS) {
    for (const [i, specs] of ORDERINGS.entries()) {
      it(`${algorithm}, ordering ${i}`, () => {
        const policy = policyOf(algorithm, specs)
        const slow = evaluatePolicy(policy, request, 'deny')
        const fast = evaluatePolicyFast(policy, request, 'deny')
        expect(fast).toBe(slow.allowed)
      })
    }
  }
})
