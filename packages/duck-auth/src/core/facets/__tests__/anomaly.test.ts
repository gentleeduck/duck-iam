/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { impossibleTravelDetector } from '../../anomaly/impossible-travel'
import { InMemoryEvents } from '../../events'
import type { Anomaly } from '../../types/anomaly'
import type { Identity } from '../../types/identity'
import type { Session } from '../../types/session'
import { AnomalyFacet, DEFAULT_ANOMALY_CONFIG } from '../anomaly'

const identity: Identity.IIdentity = { id: 'u', providers: [], version: 1, createdAt: 0, updatedAt: 0 }
const session: Session.ISession = {
  id: 'sid',
  identityId: 'u',
  kind: 'user',
  aal: 1,
  factors: [],
  createdAt: 0,
  rotatedAt: 0,
  expiresAt: Date.now() + 60_000,
  absoluteExpiresAt: Date.now() + 60_000,
  fresh: true,
}

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

  it('integrates with impossible-travel detector', async () => {
    const now = Date.now()
    facet.register(
      impossibleTravelDetector({
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
})
