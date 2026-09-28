import { test } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast, evaluatePolicyFast } from '../evaluate'
import { indexPolicy } from '../evaluate.libs'

function buildPolicy(numRules: number, withConditions: boolean): AccessControl.IPolicy {
  const rules: AccessControl.IRule[] = []
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

test('evaluatePolicyFast', async ({ bench }) => {
  const tiny = buildPolicy(5, false)
  const medium = buildPolicy(50, false)
  const large = buildPolicy(500, false)
  const conditional = buildPolicy(50, true)

  await bench.compare(
    bench('5 rules, unconditional', () => {
      evaluatePolicyFast(tiny, req)
    }),
    bench('50 rules, unconditional', () => {
      evaluatePolicyFast(medium, req)
    }),
    bench('500 rules, unconditional', () => {
      evaluatePolicyFast(large, req)
    }),
    bench('50 rules with conditions', () => {
      evaluatePolicyFast(conditional, req)
    }),
  )
})

test('indexPolicy (cache hit)', async ({ bench }) => {
  const policy = buildPolicy(100, false)
  // Warm the cache once.
  indexPolicy(policy)

  await bench('cache hit', () => {
    indexPolicy(policy)
  }).run()
})

test('indexPolicy (cold build)', async ({ bench }) => {
  await bench('100 rules cold build', () => {
    // Use a fresh policy object each invocation to defeat the WeakMap cache.
    indexPolicy(buildPolicy(100, false))
  }).run()
})

test('evaluate vs evaluateFast', async ({ bench }) => {
  const policies = [buildPolicy(50, false)]

  await bench.compare(
    bench('evaluate (trace path)', () => {
      evaluate(policies, req)
    }),
    bench('evaluateFast (production path)', () => {
      evaluateFast(policies, req)
    }),
  )
})

test('cross-policy combine', async ({ bench }) => {
  const policies = Array.from({ length: 10 }, () => buildPolicy(20, false))

  await bench.compare(
    bench('combine=and x 10 policies', () => {
      evaluateFast(policies, req, 'deny', 'and')
    }),
    bench('combine=allow-overrides x 10 policies', () => {
      evaluateFast(policies, req, 'deny', 'allow-overrides')
    }),
  )
})
