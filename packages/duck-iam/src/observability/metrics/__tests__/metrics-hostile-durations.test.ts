import { describe, expect, it } from 'vitest'
import type { IamEngineTypes } from '../../../core/engine/engine.types'
import { iamCreateMetricsAggregator } from '../index'

function event(durationMs: number): IamEngineTypes.IMetricsEvent {
  return {
    action: 'read',
    allowed: true,
    durationMs,
    failOpen: false,
    mode: 'production',
    resource: 'post',
    subjectId: 'u',
  }
}

// A backwards clock or a hand-built event can put NaN, Infinity or a negative into the ring, and one NaN makes the
// percentile sort meaningless from then on - a single bad sample flatlines the latency dashboard.
describe('the latency ring buffer refuses samples that are not durations', () => {
  const REJECTED: ReadonlyArray<{ name: string; value: number }> = [
    { name: 'NaN', value: Number.NaN },
    { name: 'Infinity', value: Number.POSITIVE_INFINITY },
    { name: '-Infinity', value: Number.NEGATIVE_INFINITY },
    { name: 'a negative duration', value: -1 },
  ]

  for (const { name, value } of REJECTED) {
    it(`drops ${name} without disturbing the surrounding samples`, () => {
      const m = iamCreateMetricsAggregator()
      m.record(event(10))
      m.record(event(value))
      m.record(event(30))
      const snap = m.snapshot()
      expect(snap.samples).toBe(2)
      expect(snap.max).toBe(30)
      expect(snap.p50).toBe(10)
      // The event still counts: the verdict happened, only its timing is unusable.
      expect(snap.total).toBe(3)
      expect(snap.allow).toBe(3)
    })
  }

  // Boundary: zero is a legitimate duration for a cache hit, so the guard cannot be widened to `> 0`.
  it('keeps a zero-millisecond sample', () => {
    const m = iamCreateMetricsAggregator()
    m.record(event(0))
    expect(m.snapshot().samples).toBe(1)
    expect(m.snapshot().max).toBe(0)
  })

  it('reports no samples at all when every duration is unusable', () => {
    const m = iamCreateMetricsAggregator()
    for (const { value } of REJECTED) m.record(event(value))
    const snap = m.snapshot()
    expect(snap.samples).toBe(0)
    expect(snap.total).toBe(4)
    expect([snap.p50, snap.p95, snap.p99, snap.max]).toEqual([0, 0, 0, 0])
  })
})
