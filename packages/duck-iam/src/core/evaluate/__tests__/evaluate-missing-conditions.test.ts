import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { indexPolicy } from '../evaluate.libs'

// A stored rule can lack `conditions`. Indexing must neither throw nor decide it, so both engines reach the same
// throw and the engine folds it into a fail-closed Indeterminate.
/** Built through JSON, the way such a row arrives, so no cast stands in for the adapter. */
function ruleWithoutConditions(overrides: Partial<AccessControl.IRule> = {}): AccessControl.IRule {
  return JSON.parse(
    JSON.stringify({
      actions: ['read'],
      effect: 'deny',
      id: 'r-no-cond',
      priority: 10,
      resources: ['post'],
      ...overrides,
    }),
  )
}

function policyOf(rules: AccessControl.IRule[]): AccessControl.IPolicy {
  return { id: 'p1', name: 'p1', algorithm: 'deny-overrides', rules }
}

describe('indexPolicy with a rule missing `conditions`', () => {
  it('does not throw on the precompute path (no wildcards present)', () => {
    expect(() => indexPolicy(policyOf([ruleWithoutConditions()]))).not.toThrow()
  })

  // Not "unconditional": `evalConditionGroup` throws on an absent group, so the fast path must reach the same throw.
  it('flags a missing `conditions` as needing evaluation', () => {
    const index = indexPolicy(policyOf([ruleWithoutConditions()]))
    const entries = index.byActionResource.get('read')?.get('post')
    expect(entries).toBeDefined()
    expect(entries?.[0]?.hasConditions).toBe(true)
  })

  it('keeps it out of the precompute table', () => {
    const index = indexPolicy(policyOf([ruleWithoutConditions()]))
    expect(index.precomputed.size).toBe(0)
  })

  it('does not throw when a sibling bucket entry also lacks conditions', () => {
    const rules = [
      ruleWithoutConditions({ id: 'a', effect: 'allow' }),
      ruleWithoutConditions({ id: 'b', effect: 'deny' }),
    ]
    expect(() => indexPolicy(policyOf(rules))).not.toThrow()
  })
})
