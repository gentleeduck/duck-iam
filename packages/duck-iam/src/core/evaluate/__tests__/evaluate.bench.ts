import { bench, describe } from 'vitest'
import type { IamAccessControl, IamRequest } from '../../types'
import { iamEvaluate, iamEvaluateFast, iamEvaluatePolicyFast } from '../evaluate'
import { iamIndexPolicy } from '../evaluate.libs'

function buildPolicy(numRules: number, withConditions: boolean): IamAccessControl.IPolicy {
  const rules: IamAccessControl.IRule[] = []
  const actions = ['read', 'create', 'update', 'delete', 'manage']
  const resources = ['post', 'comment', 'user', 'org', 'org:project']
  for (let i = 0; i < numRules; i++) {
    rules.push({
      id: `r${i}`,
      effect: i % 7 === 0 ? 'deny' : 'allow',
      priority: i % 20,
      actions: [actions[i % actions.length]!],
      resources: [resources[i % resources.length]!],
      conditions: withConditions
        ? { all: [{ field: 'subject.attributes.status', operator: 'eq', value: 'active' }] }
        : { all: [] },
    })
  }
  return { id: 'p', name: 'P', algorithm: 'deny-overrides', rules }
}

const req: IamRequest.IAccessRequest = {
  subject: { id: 'u1', roles: ['editor'], attributes: { status: 'active' } },
  action: 'read',
  resource: { type: 'post', attributes: {} },
}

describe('evaluatePolicyFast', () => {
  const tiny = buildPolicy(5, false)
  const medium = buildPolicy(50, false)
  const large = buildPolicy(500, false)
  const conditional = buildPolicy(50, true)

  bench('5 rules, unconditional', () => {
    iamEvaluatePolicyFast(tiny, req)
  })

  bench('50 rules, unconditional', () => {
    iamEvaluatePolicyFast(medium, req)
  })

  bench('500 rules, unconditional', () => {
    iamEvaluatePolicyFast(large, req)
  })

  bench('50 rules with conditions', () => {
    iamEvaluatePolicyFast(conditional, req)
  })
})

describe('iamIndexPolicy (cache hit)', () => {
  const policy = buildPolicy(100, false)
  // Warm the cache once.
  iamIndexPolicy(policy)

  bench('cache hit', () => {
    iamIndexPolicy(policy)
  })
})

describe('iamIndexPolicy (cold build)', () => {
  bench('100 rules cold build', () => {
    // Use a fresh policy object each invocation to defeat the WeakMap cache.
    iamIndexPolicy(buildPolicy(100, false))
  })
})

describe('evaluate vs iamEvaluateFast', () => {
  const policies = [buildPolicy(50, false)]

  bench('evaluate (trace path)', () => {
    iamEvaluate(policies, req)
  })

  bench('evaluateFast (production path)', () => {
    iamEvaluateFast(policies, req)
  })
})

describe('cross-policy combine', () => {
  const policies = Array.from({ length: 10 }, () => buildPolicy(20, false))

  bench('combine=and x 10 policies', () => {
    iamEvaluateFast(policies, req, 'deny', 'and')
  })

  bench('combine=allow-overrides x 10 policies', () => {
    iamEvaluateFast(policies, req, 'deny', 'allow-overrides')
  })
})
