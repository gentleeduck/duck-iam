import { describe, expect, it } from 'vitest'
import { detail, fault } from '../brand'

describe('detail and fault', () => {
  it('detail() is the status at runtime, nothing else', () => {
    expect(detail<{ x: number }>(400)).toBe(400)
  })

  it('fault() is also the status at runtime, with or without a meta type argument', () => {
    expect(fault(404)).toBe(404)
    expect(fault<{ x: number }>(404)).toBe(404)
  })

  it('both build a registry that still satisfies a plain Record<string, number>', () => {
    const registry = {
      TEST_BARE: 500,
      TEST_DETAIL: detail<{ field: string }>(400),
      TEST_FAULT: fault<{ adapter: string }>(500),
    } as const satisfies Record<string, number>
    expect(Object.values(registry).every((status) => typeof status === 'number')).toBe(true)
  })
})
