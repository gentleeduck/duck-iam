import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { indexPolicy } from '../evaluate.libs'

/**
 * `IRule.conditions` is required by the type and by the JSON schema, but neither
 * `validateRuleShape` nor the memory/http adapters enforce it, so a rule loaded
 * from storage can reach `indexPolicy` without it. `'all' in undefined` throws a
 * TypeError that the engine swallows via `onPolicyError`, dropping the whole
 * policy - which turns a deny into an allow under `allowFailOpen`.
 */
function ruleWithoutConditions(overrides: Partial<AccessControl.IRule> = {}): AccessControl.IRule {
  const rule = {
    id: 'r-no-cond',
    effect: 'deny' as const,
    priority: 10,
    actions: ['read'],
    resources: ['post'],
    ...overrides,
  }
  // Deliberately omitted, mirroring an adapter row that lacks the key.
  return rule as AccessControl.IRule
}

function policyOf(rules: AccessControl.IRule[]): AccessControl.IPolicy {
  return { id: 'p1', name: 'p1', algorithm: 'deny-overrides', rules }
}

describe('indexPolicy with a rule missing `conditions`', () => {
  it('does not throw on the precompute path (no wildcards present)', () => {
    expect(() => indexPolicy(policyOf([ruleWithoutConditions()]))).not.toThrow()
  })

  it('treats a missing `conditions` as unconditional', () => {
    const index = indexPolicy(policyOf([ruleWithoutConditions()]))
    const entries = index.byActionResource.get('read\0post')
    expect(entries).toBeDefined()
    expect(entries?.[0]?.hasConditions).toBe(false)
  })

  it('does not throw when a sibling bucket entry also lacks conditions', () => {
    const rules = [
      ruleWithoutConditions({ id: 'a', effect: 'allow' }),
      ruleWithoutConditions({ id: 'b', effect: 'deny' }),
    ]
    expect(() => indexPolicy(policyOf(rules))).not.toThrow()
  })
})
