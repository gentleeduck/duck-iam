import { describe, expect, it } from 'vitest'
import type { IamEngineTypes } from '../../../core/engine/engine.types'
import { iamCreateMetricsAggregator } from '../index'

function fakeEvent(durationMs: number, allowed = true, failOpen = false): IamEngineTypes.IMetricsEvent {
  return {
    subjectId: 'u',
    action: 'read',
    resource: 'post',
    allowed,
    durationMs,
    mode: 'production',
    failOpen,
  }
}

describe('iamCreateMetricsAggregator', () => {
  it('counts allow / deny verdicts', () => {
    const m = iamCreateMetricsAggregator()
    for (let i = 0; i < 7; i++) m.record(fakeEvent(1, true))
    for (let i = 0; i < 3; i++) m.record(fakeEvent(1, false))
    const s = m.snapshot()
    expect(s.total).toBe(10)
    expect(s.allow).toBe(7)
    expect(s.deny).toBe(3)
  })

  it('computes p50 / p95 / p99 over the rolling window', () => {
    const m = iamCreateMetricsAggregator()
    for (let i = 1; i <= 100; i++) m.record(fakeEvent(i))
    const s = m.snapshot()
    expect(s.p50).toBeGreaterThanOrEqual(49)
    expect(s.p50).toBeLessThanOrEqual(51)
    expect(s.p95).toBeGreaterThanOrEqual(94)
    expect(s.p95).toBeLessThanOrEqual(96)
    expect(s.p99).toBeGreaterThanOrEqual(98)
    expect(s.p99).toBeLessThanOrEqual(100)
    expect(s.max).toBe(100)
    expect(s.samples).toBe(100)
  })

  it('evicts oldest samples beyond sampleSize', () => {
    const m = iamCreateMetricsAggregator({ sampleSize: 10 })
    for (let i = 1; i <= 100; i++) m.record(fakeEvent(i))
    const s = m.snapshot()
    expect(s.samples).toBe(10)
    expect(s.total).toBe(100)
    // After 100 events with cap 10, only durations 91..100 remain - max is 100, p50 ~95.
    expect(s.max).toBe(100)
    expect(s.p50).toBeGreaterThanOrEqual(94)
  })

  it('reset zeroes counters but keeps the buffer allocation', () => {
    const m = iamCreateMetricsAggregator()
    m.record(fakeEvent(5))
    m.reset()
    const s = m.snapshot()
    expect(s.total).toBe(0)
    expect(s.allow).toBe(0)
    expect(s.deny).toBe(0)
    expect(s.samples).toBe(0)
  })

  it('returns zeros on empty window', () => {
    const m = iamCreateMetricsAggregator()
    const s = m.snapshot()
    expect(s).toEqual({ total: 0, allow: 0, deny: 0, failOpen: 0, p50: 0, p95: 0, p99: 0, max: 0, samples: 0 })
  })

  it('counts failOpen as a subset of allow', () => {
    const m = iamCreateMetricsAggregator()
    // 5 normal allows
    for (let i = 0; i < 5; i++) m.record(fakeEvent(1, true, false))
    // 3 fail-open allows
    for (let i = 0; i < 3; i++) m.record(fakeEvent(1, true, true))
    // 2 denies
    for (let i = 0; i < 2; i++) m.record(fakeEvent(1, false, false))
    const s = m.snapshot()
    expect(s.allow).toBe(8)
    expect(s.deny).toBe(2)
    expect(s.failOpen).toBe(3)
    expect(s.total).toBe(10)
  })

  it('reset zeroes failOpen counter', () => {
    const m = iamCreateMetricsAggregator()
    m.record(fakeEvent(1, true, true))
    m.reset()
    expect(m.snapshot().failOpen).toBe(0)
  })
})

describe('iamCreateMetricsAggregator rolling-window semantics', () => {
  it('reports the window max, not the all-time max', () => {
    const m = iamCreateMetricsAggregator({ sampleSize: 3 })
    m.record(fakeEvent(100))
    m.record(fakeEvent(1))
    m.record(fakeEvent(2))
    m.record(fakeEvent(3))
    const s = m.snapshot()
    expect(s.max).toBe(3)
    expect(s.samples).toBe(3)
    expect(s.total).toBe(4)
  })

  it('snapshot does not reorder the ring buffer', () => {
    const m = iamCreateMetricsAggregator({ sampleSize: 4 })
    for (const d of [40, 30, 20, 10]) m.record(fakeEvent(d))
    expect(m.snapshot().max).toBe(40)
    // Overwrites the oldest slot (40). Window is now {5, 30, 20, 10}.
    m.record(fakeEvent(5))
    expect(m.snapshot().max).toBe(30)
  })

  it('keeps only the newest sample at sampleSize 1', () => {
    const m = iamCreateMetricsAggregator({ sampleSize: 1 })
    m.record(fakeEvent(5))
    m.record(fakeEvent(9))
    m.record(fakeEvent(2))
    const s = m.snapshot()
    expect(s.samples).toBe(1)
    expect(s.max).toBe(2)
    expect(s.p50).toBe(2)
    expect(s.p99).toBe(2)
    expect(s.total).toBe(3)
  })

  it('starts a fresh window after reset', () => {
    const m = iamCreateMetricsAggregator({ sampleSize: 10 })
    for (const d of [100, 200, 300]) m.record(fakeEvent(d))
    m.reset()
    m.record(fakeEvent(7))
    const s = m.snapshot()
    expect(s.samples).toBe(1)
    expect(s.max).toBe(7)
    expect(s.p50).toBe(7)
    expect(s.total).toBe(1)
  })

  it('leaves allow at zero for a deny-only stream', () => {
    const m = iamCreateMetricsAggregator()
    for (const d of [4, 8]) m.record(fakeEvent(d, false))
    const s = m.snapshot()
    expect(s.allow).toBe(0)
    expect(s.deny).toBe(2)
    expect(s.failOpen).toBe(0)
    expect(s.max).toBe(8)
  })
})
