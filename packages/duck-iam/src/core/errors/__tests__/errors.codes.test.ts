import { describe, expect, it } from 'vitest'
import { detail, fault, IAM_ERRORS } from '../errors.codes'

describe('IAM_ERRORS', () => {
  it('keeps a declared status a plain number, which is what every reader of the map takes it for', () => {
    expect(IAM_ERRORS.IAM_ROLE_NOT_FOUND).toBe(404)
    expect(Object.values(IAM_ERRORS).every((status) => typeof status === 'number')).toBe(true)
  })

  it('has no duplicate keys across the whole registry', () => {
    const keys = Object.keys(IAM_ERRORS)
    expect(new Set(keys).size).toBe(keys.length)
  })
})

describe('detail and fault', () => {
  it('detail() is the status at runtime, nothing else', () => {
    expect(detail<{ x: number }>(400)).toBe(400)
  })

  it('fault() is also the status at runtime', () => {
    expect(fault(404)).toBe(404)
    expect(fault<{ x: number }>(404)).toBe(404)
  })
})
