import { describe, expect, it } from 'vitest'
import { MAX_CONDITION_VALUE_LENGTH, validatePolicy } from '../index'

function policyWithCondValue(value: unknown) {
  return {
    id: 'p1',
    name: 'p1',
    algorithm: 'allow-overrides',
    rules: [
      {
        id: 'r1',
        effect: 'allow',
        priority: 0,
        actions: ['read'],
        resources: ['post'],
        conditions: {
          all: [{ field: 'subject.id', operator: 'eq', value }],
        },
      },
    ],
  }
}

describe('validatePolicy condition value length cap', () => {
  it('rejects a string value exceeding MAX_CONDITION_VALUE_LENGTH', () => {
    const evil = 'X'.repeat(MAX_CONDITION_VALUE_LENGTH + 1)
    const result = validatePolicy(policyWithCondValue(evil))
    expect(result.valid).toBe(false)
    const limit = result.issues.find((i) => i.code === 'LIMIT_EXCEEDED' && i.path?.includes('value'))
    expect(limit).toBeDefined()
    expect(limit?.message).toContain(`${MAX_CONDITION_VALUE_LENGTH + 1} chars`)
    expect(limit?.message).not.toContain(evil.slice(0, 100))
  })

  it('rejects a 10 MiB string value without inflating the diagnostic message', () => {
    const evil = 'Y'.repeat(10 * 1024 * 1024)
    const result = validatePolicy(policyWithCondValue(evil))
    expect(result.valid).toBe(false)
    const totalMsgBytes = result.issues.reduce((sum, i) => sum + (i.message?.length ?? 0), 0)
    expect(totalMsgBytes).toBeLessThan(2_000)
  })

  it('rejects an `in` array containing an oversized string element', () => {
    const evil = 'Z'.repeat(MAX_CONDITION_VALUE_LENGTH + 1)
    const result = validatePolicy({
      id: 'p1',
      name: 'p1',
      algorithm: 'allow-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 0,
          actions: ['read'],
          resources: ['post'],
          conditions: {
            all: [{ field: 'subject.id', operator: 'in', value: ['short', evil, 'also-short'] }],
          },
        },
      ],
    })
    expect(result.valid).toBe(false)
    const limit = result.issues.find((i) => i.code === 'LIMIT_EXCEEDED' && i.path?.includes('value[1]'))
    expect(limit).toBeDefined()
    expect(limit?.message).not.toContain(evil.slice(0, 100))
  })

  it('accepts a string value just at the cap', () => {
    const ok = 'X'.repeat(MAX_CONDITION_VALUE_LENGTH)
    const result = validatePolicy(policyWithCondValue(ok))
    const limit = result.issues.find((i) => i.code === 'LIMIT_EXCEEDED' && i.path?.includes('value'))
    expect(limit).toBeUndefined()
  })

  it('accepts a normal-length value (UUID, JWT sub, etc.)', () => {
    const result = validatePolicy(policyWithCondValue('a1b2c3d4-e5f6-7890-abcd-ef1234567890'))
    const limit = result.issues.find((i) => i.code === 'LIMIT_EXCEEDED' && i.path?.includes('value'))
    expect(limit).toBeUndefined()
  })

  it('does not gate non-string values (numbers / booleans pass through)', () => {
    const numResult = validatePolicy(policyWithCondValue(42))
    expect(numResult.issues.every((i) => i.code !== 'LIMIT_EXCEEDED' || !i.path?.includes('value'))).toBe(true)
    const boolResult = validatePolicy(policyWithCondValue(true))
    expect(boolResult.issues.every((i) => i.code !== 'LIMIT_EXCEEDED' || !i.path?.includes('value'))).toBe(true)
  })

  it('caps the UNRESOLVABLE_VALUE diagnostic when value starts with $ but is oversized', () => {
    const evilRef = `$${'X'.repeat(MAX_CONDITION_VALUE_LENGTH + 1)}`
    const result = validatePolicy(policyWithCondValue(evilRef))
    expect(result.valid).toBe(false)
    // The LIMIT_EXCEEDED error fires first; the UNRESOLVABLE_VALUE
    // warning may still fire but never with the raw value interpolated
    // beyond the cap, because the LIMIT_EXCEEDED gates evaluation.
    const totalMsgBytes = result.issues.reduce((sum, i) => sum + (i.message?.length ?? 0), 0)
    expect(totalMsgBytes).toBeLessThan(2_000)
  })

  it('one oversized element triggers only one LIMIT_EXCEEDED issue per condition', () => {
    const evil = 'Z'.repeat(MAX_CONDITION_VALUE_LENGTH + 1)
    const result = validatePolicy({
      id: 'p1',
      name: 'p1',
      algorithm: 'allow-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 0,
          actions: ['read'],
          resources: ['post'],
          conditions: {
            all: [
              {
                field: 'subject.id',
                operator: 'in',
                value: [evil, evil, evil],
              },
            ],
          },
        },
      ],
    })
    expect(result.valid).toBe(false)
    const limitErrors = result.issues.filter(
      (i) => i.code === 'LIMIT_EXCEEDED' && i.path?.startsWith('rules[0].conditions'),
    )
    // One issue per condition is enough; we don't burn issue-array memory
    // on every element of a hostile array.
    expect(limitErrors.length).toBe(1)
  })
})
