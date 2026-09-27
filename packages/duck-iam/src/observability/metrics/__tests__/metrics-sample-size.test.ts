import { describe, expect, it } from 'vitest'
import { hasIamErrorCode } from '../../../core/errors'
import { iamCreateMetricsAggregator } from '../index'

function throwsMetricsSampleSizeInvalid(fn: () => unknown): boolean {
  try {
    fn()
    return false
  } catch (err) {
    return hasIamErrorCode(err, 'IAM_METRICS_SAMPLE_SIZE_INVALID')
  }
}

// `sampleSize` sizes a ring buffer: `0` makes `head % cap` NaN and swallows every sample, and a negative,
// fractional or infinite value raises a `Float64Array` RangeError that never names the option.
describe('iamCreateMetricsAggregator sampleSize validation', () => {
  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])('rejects %s with an error naming sampleSize', (bad) => {
    expect(throwsMetricsSampleSizeInvalid(() => iamCreateMetricsAggregator({ sampleSize: bad }))).toBe(true)
  })

  it('accepts a positive integer', () => {
    expect(() => iamCreateMetricsAggregator({ sampleSize: 1 })).not.toThrow()
  })
})
