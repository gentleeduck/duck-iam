import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine/engine'
import type { AccessControl } from '../../types'
import { validatePolicy } from '../../validate'

/**
 * `validatePolicy` rejects an algorithm outside the four combiners, but adapter
 * reads are not re-validated, so a hand-edited or migrated row reaches the
 * engine. Both modes must treat it as invalid data: the interpreter throws on
 * `combiners[algorithm]` and denies, and production compiled the same row to an
 * unconditional CONST_ALLOW because cell kind is decided from `rule.effect`
 * alone. One bad column granted in production and denied in development.
 */
// The deny sits on a *different* cell from the request. With both rules on the
// queried cell the two modes agree for an unrelated reason (the deny wins
// either way) and the divergence is invisible - that shape is not a test.
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

  // The residual path diverged too: it does reach `evaluatePolicyFast`, but the
  // final scan there had no algorithm guard and silently ran as first-match.
  // Both halves needed a fix, so keep both cases.
  it.each(['development', 'production'] as const)('denies in %s mode - residual path', async (mode) => {
    const wild = policyWith('deny-overides', [{ ...allowRead, actions: ['*'] }, denyElsewhere])
    expect(await engineFor(mode, wild).can('u1', 'read', { type: 'doc', attributes: {} })).toBe(false)
  })

  // The control: the same policy with the algorithm spelled correctly is a
  // deny-overrides policy carrying a deny, so it denies for a real reason. If
  // this ever went green while the assertions above were also green because
  // everything denies, the test above would be pinning nothing.
  it('allows in both modes once the algorithm names a real combiner', async () => {
    const fixed = policyWith('deny-overrides', [allowRead, denyElsewhere])
    for (const mode of ['development', 'production'] as const) {
      expect(await engineFor(mode, fixed).can('u1', 'read', { type: 'doc', attributes: {} })).toBe(true)
    }
  })
})
