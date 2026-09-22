import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine/engine'
import type { AccessControl } from '../../types'
import { validatePolicy } from '../../validate'

// An unknown algorithm from an unvalidated row must deny in both modes.
// The deny sits on a different cell: on the queried cell the modes would agree for an unrelated reason.
const allowRead: AccessControl.IRule = {
  id: 'r-allow',
  effect: 'allow',
  priority: 1,
  actions: ['read'],
  resources: ['doc'],
  conditions: { all: [] },
}
const denyElsewhere: AccessControl.IRule = {
  id: 'r-deny',
  effect: 'deny',
  priority: 10,
  actions: ['delete'],
  resources: ['secret'],
  conditions: { all: [] },
}

function policyWith(algorithm: string, rules: AccessControl.IRule[]): AccessControl.IPolicy {
  // Through JSON, the way an adapter row arrives - `algorithm` is typed as a
  // union, and a literal would not compile.
  return JSON.parse(JSON.stringify({ id: 'p-bogus', name: 'bogus', algorithm, rules }))
}

const bogus = policyWith('deny-overides', [allowRead, denyElsewhere]) // one letter short

function engineFor(mode: 'development' | 'production', policy: AccessControl.IPolicy) {
  const adapter = new IamMemoryAdapter({
    roles: [],
    policies: [policy],
    assignments: { u1: [] },
    attributes: { u1: {} },
  })
  return new IamEngine({ adapter, defaultEffect: 'deny', mode })
}

describe('a policy with an unrecognised combining algorithm', () => {
  it('is rejected by validatePolicy', () => {
    const result = validatePolicy(bogus)
    expect(result.valid).toBe(false)
    expect(result.issues.map((i) => i.code)).toContain('INVALID_ALGORITHM')
  })

  it.each(['development', 'production'] as const)('denies in %s mode - flat cell', async (mode) => {
    expect(await engineFor(mode, bogus).can('u1', 'read', { type: 'doc', attributes: {} })).toBe(false)
  })

  // The residual path reaches `evaluatePolicyFast`, which must refuse the unknown algorithm too.
  it.each(['development', 'production'] as const)('denies in %s mode - residual path', async (mode) => {
    const wild = policyWith('deny-overides', [{ ...allowRead, actions: ['*'] }, denyElsewhere])
    expect(await engineFor(mode, wild).can('u1', 'read', { type: 'doc', attributes: {} })).toBe(false)
  })

  // Control: with a real algorithm the request is allowed, so the denials above are not "everything denies".
  it('allows in both modes once the algorithm names a real combiner', async () => {
    const fixed = policyWith('deny-overrides', [allowRead, denyElsewhere])
    for (const mode of ['development', 'production'] as const) {
      expect(await engineFor(mode, fixed).can('u1', 'read', { type: 'doc', attributes: {} })).toBe(true)
    }
  })
})
