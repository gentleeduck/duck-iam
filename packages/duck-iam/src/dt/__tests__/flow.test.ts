import { describe, expect, it, vi } from 'vitest'
import { iamCreateFlowRecorder } from '../lib/flow'

function base(overrides: Partial<Parameters<ReturnType<typeof iamCreateFlowRecorder>['record']>[0]> = {}) {
  return {
    action: 'read',
    allowed: true,
    resource: 'post',
    subjectId: 'u1',
    ...overrides,
  }
}

describe('iamCreateFlowRecorder', () => {
  it('assigns sequential ids starting at 1', () => {
    const rec = iamCreateFlowRecorder()
    expect(rec.record(base()).id).toBe(1)
    expect(rec.record(base()).id).toBe(2)
    expect(rec.record(base()).id).toBe(3)
  })

  it('stamps ts with Date.now() when omitted, and honours an explicit ts', () => {
    const rec = iamCreateFlowRecorder()
    const before = Date.now()
    const auto = rec.record(base())
    expect(auto.ts).toBeGreaterThanOrEqual(before)
    expect(auto.ts).toBeLessThanOrEqual(Date.now())

    const explicit = rec.record(base({ ts: 12345 }))
    expect(explicit.ts).toBe(12345)
  })

  it('lists newest-first', () => {
    const rec = iamCreateFlowRecorder()
    rec.record(base({ action: 'first' }))
    rec.record(base({ action: 'second' }))
    expect(rec.list().map((e) => e.action)).toEqual(['second', 'first'])
  })

  it('carries every optional field through onto the stored entry', () => {
    const rec = iamCreateFlowRecorder()
    const entry = rec.record(
      base({
        decidingPolicy: 'p1',
        decidingRule: 'r1',
        durationMs: 4,
        environment: { ip: '127.0.0.1' },
        reason: 'matched',
        resourceId: 'post-1',
        scope: 'org-1',
      }),
    )
    expect(entry).toMatchObject({
      decidingPolicy: 'p1',
      decidingRule: 'r1',
      durationMs: 4,
      environment: { ip: '127.0.0.1' },
      reason: 'matched',
      resourceId: 'post-1',
      scope: 'org-1',
    })
    expect(rec.get(entry.id)).toEqual(entry)
  })

  it('get() returns undefined for an unknown id', () => {
    const rec = iamCreateFlowRecorder()
    rec.record(base())
    expect(rec.get(999)).toBeUndefined()
  })

  it('caps the buffer at bufferSize, dropping the oldest entries', () => {
    const rec = iamCreateFlowRecorder({ bufferSize: 2 })
    rec.record(base({ action: 'a' }))
    rec.record(base({ action: 'b' }))
    rec.record(base({ action: 'c' }))
    expect(rec.list()).toHaveLength(2)
    expect(rec.list().map((e) => e.action)).toEqual(['c', 'b'])
  })

  it('keeps ids monotonic after entries are evicted by the buffer cap', () => {
    const rec = iamCreateFlowRecorder({ bufferSize: 1 })
    rec.record(base())
    const second = rec.record(base())
    expect(second.id).toBe(2)
  })

  it('clear() empties the buffer and notifies', () => {
    const rec = iamCreateFlowRecorder()
    const listener = vi.fn()
    rec.record(base())
    rec.subscribe(listener)
    rec.clear()
    expect(rec.list()).toEqual([])
    expect(listener).toHaveBeenCalledTimes(1)
  })

  it('notifies subscribers on record, and stops after unsubscribe', () => {
    const rec = iamCreateFlowRecorder()
    const listener = vi.fn()
    const unsub = rec.subscribe(listener)
    rec.record(base())
    expect(listener).toHaveBeenCalledTimes(1)
    unsub()
    rec.record(base())
    expect(listener).toHaveBeenCalledTimes(1)
  })

  it('a throwing listener does not stop the remaining listeners', () => {
    const rec = iamCreateFlowRecorder()
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const seen: string[] = []
    rec.subscribe(() => {
      seen.push('first')
      throw new Error('boom')
    })
    rec.subscribe(() => {
      seen.push('second')
    })
    rec.record(base())
    expect(seen).toEqual(['first', 'second'])
    spy.mockRestore()
  })

  it('a throwing listener does not stop record() from returning the entry', () => {
    const rec = iamCreateFlowRecorder()
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    rec.subscribe(() => {
      throw new Error('boom')
    })
    expect(rec.record(base()).id).toBe(1)
    expect(rec.list()).toHaveLength(1)
    spy.mockRestore()
  })
})
