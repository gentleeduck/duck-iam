import { describe, expect, it } from 'vitest'
import { iamCreateMetricsAggregator } from '../index'

/**
 * `sampleSize` sizes a ring buffer: `0` turns `head % cap` into NaN and silently
 * swallows every sample, while `-1` / `1.5` / `Infinity` surface a raw
 * `Float64Array` RangeError that never mentions the option.
 */
describe('iamCreateMetricsAggregator sampleSize validation', () => {
  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])('rejects %s with an error naming sampleSize', (bad) => {
    expect(() => iamCreateMetricsAggregator({ sampleSize: bad })).toThrow(/sampleSize/)
  })

  it('accepts a positive integer', () => {
    expect(() => iamCreateMetricsAggregator({ sampleSize: 1 })).not.toThrow()
  })
})
