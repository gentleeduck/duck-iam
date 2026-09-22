import { describe, expect, it } from 'vitest'
import { validateRuleShape } from '../validate.libs'
import type { IamValidate } from '../validate.types'

function issuesFor(rule: unknown): IamValidate.IIssue[] {
  const issues: IamValidate.IIssue[] = []
  validateRuleShape(rule, 'rules[0]', issues)
  return issues
}

const base = {
  id: 'r1',
  effect: 'deny',
  priority: 10,
  actions: ['read'],
  resources: ['post'],
}

describe('validateRuleShape - conditions', () => {
  it('rejects a rule with no "conditions" key', () => {
    const errors = issuesFor(base).filter((i) => i.type === 'error')
    expect(errors.map((e) => e.path)).toContain('rules[0].conditions')
  })

  it('rejects a non-object "conditions"', () => {
    for (const bad of [null, 'all', 42, []]) {
      const errors = issuesFor({ ...base, conditions: bad }).filter((i) => i.type === 'error')
      expect(
        errors.map((e) => e.path),
        `conditions=${JSON.stringify(bad)}`,
      ).toContain('rules[0].conditions')
    }
  })

  it('accepts the builder default `{ all: [] }`', () => {
    const errors = issuesFor({ ...base, conditions: { all: [] } }).filter((i) => i.type === 'error')
    expect(errors).toEqual([])
  })

  it('rejects an empty object - the schema requires one of all/any/none', () => {
    const errors = issuesFor({ ...base, conditions: {} }).filter((i) => i.type === 'error')
    expect(errors.map((e) => e.code)).toContain('INVALID_CONDITION')
  })
})
