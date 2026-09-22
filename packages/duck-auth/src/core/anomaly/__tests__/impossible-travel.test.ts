import { describe, expect, it } from 'vitest'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { authImpossibleTravelDetector } from '../impossible-travel.detector'

const identity = makeIdentity({ id: 'u' })
const session = makeSession({ id: 'sid', identityId: 'u' })

describe('authImpossibleTravelDetector', () => {
  it('emits no signal when no last-seen recorded', async () => {
    const detector = authImpossibleTravelDetector({ getLastSeen: async () => null })
    const r = await detector.evaluate({
      session,
      identity,
      req: { now: Date.now(), geo: { lat: 51.5, lon: -0.12 } },
    })
    expect(r).toEqual([])
  })

  it('emits no signal when request has no geo', async () => {
    const detector = authImpossibleTravelDetector({
      getLastSeen: async () => ({ lat: 0, lon: 0, at: 0 }),
    })
    const r = await detector.evaluate({ session, identity, req: { now: Date.now() } })
    expect(r).toEqual([])
  })

  it('emits no signal for plausible travel (NYC -> LA over 6 hours)', async () => {
    const now = Date.now()
    const detector = authImpossibleTravelDetector({
      getLastSeen: async () => ({ lat: 40.7128, lon: -74.006, at: now - 6 * 3_600_000 }),
    })
    const r = await detector.evaluate({
      session,
      identity,
      req: { now, geo: { lat: 34.0522, lon: -118.2437 } },
    })
    expect(r).toEqual([])
  })

  it('emits high-score signal for impossible travel (NYC -> Tokyo in 30 minutes)', async () => {
    const now = Date.now()
    const detector = authImpossibleTravelDetector({
      getLastSeen: async () => ({ lat: 40.7128, lon: -74.006, at: now - 30 * 60_000 }),
    })
    const r = await detector.evaluate({
      session,
      identity,
      req: { now, geo: { lat: 35.6762, lon: 139.6503 } },
    })
    expect(r).toHaveLength(1)
    expect(r[0]?.kind).toBe('impossible-travel')
    expect(r[0]?.score).toBe(1)
    expect((r[0]?.evidence as { speedKmH: number }).speedKmH).toBeGreaterThan(20_000)
  })

  it('elapsed-ms floor suppresses sub-minute samples (NAT mobility)', async () => {
    const now = Date.now()
    const detector = authImpossibleTravelDetector({
      getLastSeen: async () => ({ lat: 40.7128, lon: -74.006, at: now - 10_000 }), // 10s ago
    })
    // 5km away. Divided by ten seconds that is 1800 km/h; divided by the 60s floor it is 300.
    const r = await detector.evaluate({
      session,
      identity,
      req: { now, geo: { lat: 40.7578, lon: -74.006 } },
    })
    expect(r).toEqual([])
  })

  it('but a global hop in the same ten seconds is not suppressed with it', async () => {
    const now = Date.now()
    const detector = authImpossibleTravelDetector({
      getLastSeen: async () => ({ lat: 40.7128, lon: -74.006, at: now - 10_000 }),
    })
    const r = await detector.evaluate({
      session,
      identity,
      req: { now, geo: { lat: 35.6762, lon: 139.6503 } },
    })
    expect(r[0]?.score).toBe(1)
  })
})
