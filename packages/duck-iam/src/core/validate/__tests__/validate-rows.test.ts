import { describe, expect, it } from 'vitest'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../index'

const validPolicy = {
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'P1',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [] },
      effect: 'allow',
      id: 'r1',
      priority: 10,
      resources: ['post'],
    },
  ],
}

const validRole = { id: 'viewer', name: 'Viewer', permissions: [] }

describe('parsePolicyRow()', () => {
  it('returns the row itself when the policy validates', () => {
    const parsed = parsePolicyRow(validPolicy)
    expect(parsed).toBe(validPolicy)
  })

  it.each([
    ['null', null],
    ['an array', []],
    ['a string', 'p1'],
    ['a number', 42],
  ])('returns null for %s', (_label, raw) => {
    expect(parsePolicyRow(raw)).toBeNull()
  })

  it('returns null when a required field is missing', () => {
    const { rules: _rules, ...noRules } = validPolicy
    expect(parsePolicyRow(noRules)).toBeNull()
    expect(parsePolicyRow({ ...validPolicy, id: '' })).toBeNull()
    expect(parsePolicyRow({ ...validPolicy, algorithm: 'nope' })).toBeNull()
  })

  it('still returns the row when validation only produced warnings', () => {
    const broad = {
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], actions: ['*'], resources: ['*'] }],
    }
    expect(validatePolicy(broad).issues.some((i) => i.code === 'BROAD_ALLOW')).toBe(true)
    expect(parsePolicyRow(broad)).toBe(broad)
  })
})

describe('parseRoleRow()', () => {
  it('returns the row itself when the role validates', () => {
    expect(parseRoleRow(validRole)).toBe(validRole)
  })

  it.each([
    ['null', null],
    ['an array', []],
    ['a string', 'viewer'],
  ])('returns null for %s', (_label, raw) => {
    expect(parseRoleRow(raw)).toBeNull()
  })

  it('returns null when id is empty or permissions are missing', () => {
    expect(parseRoleRow({ id: '', permissions: [] })).toBeNull()
    expect(parseRoleRow({ id: 'viewer' })).toBeNull()
    expect(parseRoleRow({ id: 'viewer', inherits: 'admin', permissions: [] })).toBeNull()
  })
})

describe('validateRole() - optional inherits', () => {
  it('treats null inherits as absent', () => {
    const r = validateRole({ id: 'viewer', inherits: null, permissions: [] })
    expect(r.valid).toBe(true)
    expect(r.issues).toEqual([])
  })

  it('accepts an empty inherits array', () => {
    expect(validateRole({ id: 'viewer', inherits: [], permissions: [] }).valid).toBe(true)
  })
})

describe('validatePolicy() - numeric and malformed boundaries', () => {
  const withRule = (overrides: Record<string, unknown>) => ({
    ...validPolicy,
    rules: [{ ...validPolicy.rules[0], ...overrides }],
  })

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('rejects a %s rule priority, which would break priority ranking', (_label, priority) => {
    const result = validatePolicy(withRule({ priority }))
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_TYPE' && i.path === 'rules[0].priority')).toBe(true)
  })

  it.each([
    ['zero', 0],
    ['a negative integer', -5],
    ['a float', 1.5],
  ])('accepts %s as a rule priority', (_label, priority) => {
    expect(validatePolicy(withRule({ priority })).valid).toBe(true)
  })

  it('rejects a missing priority rather than defaulting it', () => {
    const { priority: _priority, ...noPriority } = validPolicy.rules[0]!
    const result = validatePolicy({ ...validPolicy, rules: [noPriority] })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.path === 'rules[0].priority')).toBe(true)
  })

  it('rejects a null rule entry', () => {
    const result = validatePolicy({ ...validPolicy, rules: [null] })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_RULE' && i.path === 'rules[0]')).toBe(true)
  })

  it('accepts a policy with an empty rules array', () => {
    expect(validatePolicy({ ...validPolicy, rules: [] }).valid).toBe(true)
  })

  it('treats null targets as absent', () => {
    expect(validatePolicy({ ...validPolicy, targets: null }).valid).toBe(true)
  })

  it('rejects an array as targets', () => {
    const result = validatePolicy({ ...validPolicy, targets: [] })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_TYPE' && i.path === 'targets')).toBe(true)
  })
})

describe('validatePolicy() - malformed conditions', () => {
  const withCondition = (condition: unknown) => ({
    ...validPolicy,
    rules: [{ ...validPolicy.rules[0], conditions: { all: [condition] } }],
  })

  it.each([
    ['an empty string', ''],
    ['a number', 7],
    ['null', null],
  ])('rejects a condition field that is %s', (_label, field) => {
    const result = validatePolicy(withCondition({ field, operator: 'eq', value: 'x' }))
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'MISSING_FIELD' || i.code === 'INVALID_CONDITION')).toBe(true)
  })

  it('rejects a condition whose operator is missing', () => {
    const result = validatePolicy(withCondition({ field: 'subject.id', value: 'x' }))
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_OPERATOR')).toBe(true)
  })

  it.each([
    ['a string', 'nope'],
    ['null', null],
    ['a number', 3],
  ])('rejects a condition item that is %s', (_label, item) => {
    const result = validatePolicy(withCondition(item))
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_CONDITION')).toBe(true)
  })

  it('rejects a group key whose value is not an array', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], conditions: { all: 'everything' } }],
    })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_CONDITION' && i.path === 'rules[0].conditions.all')).toBe(true)
  })

  it('rejects a conditions object with no all/any/none key', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], conditions: { some: [] } }],
    })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_CONDITION')).toBe(true)
  })

  it('accepts "any" and "none" groups alongside "all"', () => {
    for (const key of ['all', 'any', 'none']) {
      const result = validatePolicy({
        ...validPolicy,
        rules: [
          {
            ...validPolicy.rules[0],
            conditions: { [key]: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
          },
        ],
      })
      expect(result.valid).toBe(true)
    }
  })
})
