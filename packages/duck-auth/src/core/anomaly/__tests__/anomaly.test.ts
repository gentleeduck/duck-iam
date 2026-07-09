import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Anomaly } from '~/core/anomaly/anomaly.types'
import { authImpossibleTravelDetector } from '~/core/anomaly/impossible-travel.detector'
import { InMemoryEvents } from '~/core/events'
import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { DEFAULT_ANOMALY_CONFIG } from '../anomaly.constants'
import { AnomalyFacet } from '../anomaly.facet'

const identity = makeIdentity({ id: 'u' })
const session = makeSession({ id: 'sid', identityId: 'u' })

describe('AnomalyFacet', () => {
  let events: InMemoryEvents
  let facet: AnomalyFacet

  beforeEach(() => {
    events = new InMemoryEvents()
    facet = new AnomalyFacet(events, DEFAULT_ANOMALY_CONFIG)
  })

  it('register + list exposes detector ids', () => {
    facet.register({
      id: 'a',
      async evaluate() {
        return []
      },
    })
    facet.register({
      id: 'b',
      async evaluate() {
        return []
      },
    })
    expect(facet.list()).toEqual(['a', 'b'])
  })

  it('aggregate score = sum of signal scores; emits suspicious above threshold', async () => {
    const fakeSignal: Anomaly.Signal = { kind: 'new-device', score: 0.5, evidence: {} }
    facet.register({
      id: 'a',
      async evaluate() {
        return [fakeSignal]
      },
    })
    facet.register({
      id: 'b',
      async evaluate() {
        return [{ ...fakeSignal, kind: 'high-velocity' }]
      },
    })

    const handler = vi.fn()
    events.on('suspicious', handler)

    const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
    expect(r.score).toBeCloseTo(1.0, 5)
    expect(r.signals).toHaveLength(2)
    expect(handler).toHaveBeenCalledOnce()
    expect(handler.mock.calls[0]?.[0].signal).toContain('new-device')
    expect(handler.mock.calls[0]?.[0].signal).toContain('high-velocity')
  })

  it('does not emit when aggregate below threshold', async () => {
    facet.register({
      id: 'low',
      async evaluate() {
        return [{ kind: 'off-hours' as Anomaly.Kind, score: 0.2, evidence: {} }]
      },
    })
    const handler = vi.fn()
    events.on('suspicious', handler)
    const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
    expect(r.score).toBe(0.2)
    expect(handler).not.toHaveBeenCalled()
  })

  it('detector throw is caught + logged; other detectors still run', async () => {
    facet.register({
      id: 'broken',
      async evaluate() {
        throw new Error('boom')
      },
    })
    facet.register({
      id: 'ok',
      async evaluate() {
        return [{ kind: 'new-device' as Anomaly.Kind, score: 0.3, evidence: {} }]
      },
    })
    const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
    expect(r.signals).toHaveLength(1)
    expect(r.signals[0]?.kind).toBe('new-device')
  })

  describe('detector returns garbage - evaluator + decider stay crash-proof', () => {
    it('detector returning [null] does not crash decide() (fail-open defense)', async () => {
      facet.register({
        id: 'garbage-null',
        // @ts-expect-error: intentionally returning a wrong-shape signal to exercise the guard.
        async evaluate() {
          return [null]
        },
      })
      facet.register({
        id: 'real',
        async evaluate() {
          return [{ kind: 'new-device' as Anomaly.Kind, score: 0.3, evidence: {} }]
        },
      })
      // Without isValidSignal filtering, decide() reads `null.score` and
      // throws - auth.ts catches + drops anomaly result (silent fail-open).
      // With the guard, the bad signal is dropped, real signals remain.
      const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
      expect(r.signals).toHaveLength(1)
      expect(r.signals[0]?.kind).toBe('new-device')
      // Decision still uses the surviving real signal.
      expect(r.decision).toBe('allow') // 0.3 < default thresholds
    })

    it('detector returning non-array does not crash; skipped with log', async () => {
      facet.register({
        id: 'garbage-string',
        // @ts-expect-error: intentionally wrong return shape.
        async evaluate() {
          return 'not-an-array'
        },
      })
      facet.register({
        id: 'real',
        async evaluate() {
          return [{ kind: 'high-velocity' as Anomaly.Kind, score: 0.4, evidence: {} }]
        },
      })
      const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
      expect(r.signals).toHaveLength(1)
      expect(r.signals[0]?.kind).toBe('high-velocity')
    })

    it('signal missing kind / non-numeric score / wrong types is dropped', async () => {
      facet.register({
        id: 'mixed-garbage',
        // @ts-expect-error: intentionally wrong member shapes to test each guard branch.
        async evaluate() {
          return [
            null,
            {},
            { kind: 42, score: 0.5, evidence: {} },
            { kind: '', score: 0.5, evidence: {} },
            { kind: 'new-device', score: 'bad-string', evidence: {} },
            { kind: 'new-device' as Anomaly.Kind, score: 0.6, evidence: {} },
          ]
        },
      })
      const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
      // Only the last entry passes the guard.
      expect(r.signals).toHaveLength(1)
      expect(r.signals[0]?.score).toBe(0.6)
    })

    it('detector returning a non-finite numeric score still passes the guard but flips decide() to deny', async () => {
      facet.register({
        id: 'NaN-score',
        async evaluate() {
          return [{ kind: 'new-device' as Anomaly.Kind, score: Number.NaN, evidence: {} }]
        },
      })
      const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
      // The signal is structurally valid (score is `number` typeof). The
      // NaN guard in decide() catches it and short-circuits to 'deny'.
      expect(r.signals).toHaveLength(1)
      expect(r.decision).toBe('deny')
    })
  })

  it('integrates with impossible-travel detector', async () => {
    const now = Date.now()
    facet.register(
      authImpossibleTravelDetector({
        getLastSeen: async () => ({ lat: 40.7, lon: -74.0, at: now - 30 * 60_000 }),
      }),
    )
    const r = await facet.evaluate({
      session,
      identity,
      req: { now, geo: { lat: 35.6, lon: 139.6 } },
    })
    expect(r.signals[0]?.kind).toBe('impossible-travel')
  })

  describe('decision aggregator', () => {
    it('decide() returns allow when score is below stepUpAt', () => {
      const f = new AnomalyFacet(events)
      expect(f.decide([{ kind: 'off-hours', score: 0.3, evidence: {} }])).toBe('allow')
    })

    it('decide() returns step-up at stepUpAt threshold', () => {
      const f = new AnomalyFacet(events)
      expect(f.decide([{ kind: 'new-device', score: 0.8, evidence: {} }])).toBe('step-up')
    })

    it('decide() returns deny at denyAt threshold', () => {
      const f = new AnomalyFacet(events)
      expect(f.decide([{ kind: 'impossible-travel', score: 1.0, evidence: {} }])).toBe('deny')
    })

    it('decide() honors per-kind reaction override (step-up beats allow)', () => {
      const f = new AnomalyFacet(events, { reactions: { 'impossible-travel': 'step-up' } })
      // Score alone is below stepUpAt; reaction lifts it to step-up.
      expect(f.decide([{ kind: 'impossible-travel', score: 0.3, evidence: {} }])).toBe('step-up')
    })

    it('decide() honors per-kind reaction override (deny short-circuits over step-up)', () => {
      const f = new AnomalyFacet(events, {
        reactions: { 'impossible-travel': 'step-up', 'new-device': 'deny' },
      })
      expect(
        f.decide([
          { kind: 'impossible-travel', score: 0.3, evidence: {} },
          { kind: 'new-device', score: 0.3, evidence: {} },
        ]),
      ).toBe('deny')
    })

    it('evaluate() returns IResult shape with decision field populated', async () => {
      facet.register({
        id: 'high',
        async evaluate() {
          return [{ kind: 'impossible-travel' as Anomaly.Kind, score: 1.0, evidence: {} }]
        },
      })
      const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
      expect(r.decision).toBe('deny')
    })

    it('unregister() removes a detector by id', () => {
      facet.register({
        id: 'a',
        async evaluate() {
          return []
        },
      })
      facet.register({
        id: 'b',
        async evaluate() {
          return []
        },
      })
      facet.unregister('a')
      expect(facet.list()).toEqual(['b'])
    })

    it('unregister() unknown id is a no-op', () => {
      facet.register({
        id: 'a',
        async evaluate() {
          return []
        },
      })
      facet.unregister('missing')
      expect(facet.list()).toEqual(['a'])
    })

    it('config defaults merge with partial config (missing fields filled from DEFAULT_ANOMALY_CONFIG)', () => {
      const f = new AnomalyFacet(events, { stepUpAt: 0.5 })
      // denyAt was not supplied; default 0.95 fills in.
      expect(f.decide([{ kind: 'new-device', score: 0.95, evidence: {} }])).toBe('deny')
      // stepUpAt override of 0.5 takes effect.
      expect(f.decide([{ kind: 'new-device', score: 0.5, evidence: {} }])).toBe('step-up')
    })

    it('NaN score from a buggy detector fails CLOSED (deny), not silently allow', () => {
      const f = new AnomalyFacet(events)
      expect(f.decide([{ kind: 'new-device', score: Number.NaN, evidence: {} }])).toBe('deny')
    })

    it('+Infinity score lands on deny (regardless of other signals)', () => {
      const f = new AnomalyFacet(events)
      expect(
        f.decide([
          { kind: 'off-hours', score: 0.1, evidence: {} },
          { kind: 'new-device', score: Number.POSITIVE_INFINITY, evidence: {} },
        ]),
      ).toBe('deny')
    })

    it('evaluate() reports a meaningful score even when a detector emits NaN', async () => {
      facet.register({
        id: 'bad',
        async evaluate() {
          return [{ kind: 'new-device' as Anomaly.Kind, score: Number.NaN, evidence: {} }]
        },
      })
      facet.register({
        id: 'good',
        async evaluate() {
          return [{ kind: 'off-hours' as Anomaly.Kind, score: 0.3, evidence: {} }]
        },
      })
      const r = await facet.evaluate({ session, identity, req: { now: Date.now() } })
      // `score` field skips the NaN; `decision` still flips to deny.
      expect(r.score).toBe(0.3)
      expect(r.decision).toBe('deny')
    })
  })
})
