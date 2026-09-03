import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { indexPolicy } from '../evaluate.libs'

/**
 * `IRule.conditions` is required by the type and by the JSON schema, but neither
 * `validateRuleShape` nor the memory/http adapters enforce it, so a rule loaded
 * from storage can reach `indexPolicy` without it. Indexing such a rule must not
 * throw, and must not decide it either: the row is flagged as needing
 * evaluation so both engines hit the same `'all' in undefined` TypeError and
 * the engine folds it into a fail-closed Indeterminate.
 */
/**
 * Built through JSON, the way such a row actually arrives: `conditions` is
 * simply absent. `JSON.parse` returns `any`, so the shape the type says cannot
 * exist reaches `indexPolicy` without a cast standing in for the adapter.
 */
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

  // Not "unconditional": `evalConditionGroup` throws on an absent group, and a
  // fast path that read it as an unconditional match would honour a rule the
  // interpreter refuses. The entry is flagged as needing evaluation so both
  // engines reach the same throw, which the engine turns into a fail-closed
  // Indeterminate.
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
