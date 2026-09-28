import { describe, expect, it } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { AnomalyFacet } from '../anomaly.facet'
import type { Anomaly, AuthImpossibleTravel } from '../anomaly.types'
import { authImpossibleTravelDetector } from '../impossible-travel.detector'

const identity = makeIdentity({ id: 'u' })
const session = makeSession({ id: 'sid', identityId: 'u' })

const NOW = 1_760_000_000_000
const HOUR = 3_600_000
const NYC = { lat: 40.7128, lon: -74.006 }
const LA = { lat: 34.0522, lon: -118.2437 }
const TOKYO = { lat: 35.6762, lon: 139.6503 }

const detector = (
  last: { at: number; lat: number; lon: number } | null,
  config: Partial<AuthImpossibleTravel.Cfg> = {},
) => authImpossibleTravelDetector({ config, getLastSeen: async () => last })

const evaluate = (d: Anomaly.Detector, geo: Anomaly.RequestSnapshot['geo'], now = NOW) =>
  d.evaluate({ identity, req: { geo, now }, session })

describe('a hop too fast to be travel', () => {
  it('scores one, with the distance and speed as evidence and neither position', async () => {
    const [signal, ...rest] = await evaluate(detector({ ...NYC, at: NOW - HOUR / 2 }), TOKYO)
    expect(rest).toEqual([])
    expect(signal).toMatchObject({ kind: 'impossible-travel', score: 1 })
    expect(signal?.evidence).toEqual({
      distanceKm: 10_852,
      elapsedMs: HOUR / 2,
      intervalMs: HOUR / 2,
      speedKmH: 21_703,
      threshold: 900,
    })
  })

  it('is not flagged when the same distance took long enough', async () => {
    expect(await evaluate(detector({ ...NYC, at: NOW - 6 * HOUR }), LA)).toEqual([])
    expect(await evaluate(detector({ ...NYC, at: NOW - 13 * HOUR }), TOKYO)).toEqual([])
  })

  it('scores from half a point the moment the limit is crossed, so a sustained 1500 km/h steps up', async () => {
    // 1000 km due east in an hour: over the limit, so a mild score rather than none.
    const [mild] = await evaluate(detector({ ...NYC, at: NOW - HOUR }), { lat: NYC.lat, lon: NYC.lon + 11.8 })
    expect(mild?.score).toBeGreaterThan(0.5)
    expect(mild?.score).toBeLessThan(0.6)

    const facet = new AnomalyFacet(new InMemoryEvents())
    facet.register(detector({ ...NYC, at: NOW - HOUR }))
    const result = await facet.evaluate({
      identity,
      req: { geo: { lat: NYC.lat, lon: NYC.lon + 17.7 }, now: NOW },
      session,
    })
    expect(result.decision).toBe('step-up')
  })
})

describe('the minimum interval is a floor, not an exemption', () => {
  it('still flags a global hop inside it, and just past it', async () => {
    expect((await evaluate(detector({ ...NYC, at: NOW - 10_000 }), TOKYO))[0]?.score).toBe(1)
    expect((await evaluate(detector({ ...NYC, at: NOW - 70_000 }), TOKYO))[0]?.score).toBe(1)
  })

  it('forgives a short hop inside it, which is what it is for', async () => {
    // 5 km in 10 s is NAT mobility: 1800 km/h over ten seconds, 300 over the 60 s floor.
    expect(await evaluate(detector({ ...NYC, at: NOW - 10_000 }), { lat: NYC.lat + 0.045, lon: NYC.lon })).toEqual([])
  })

  it('reads two samples at the same instant as the floor, so a teleport across them scores', async () => {
    expect((await evaluate(detector({ ...NYC, at: NOW }), TOKYO))[0]?.score).toBe(1)
  })

  it('does not let a last-seen in the future read as a long gap, and reports the signed gap', async () => {
    // A day ahead used to be a day of travel, which switched the detector off.
    const [signal] = await evaluate(detector({ ...NYC, at: NOW + 24 * HOUR }), TOKYO)
    expect(signal).toMatchObject({ evidence: { elapsedMs: -24 * HOUR, intervalMs: 60_000 }, score: 1 })
  })
})

describe('what the detector has nothing to say about', () => {
  it('a request with no position, or half of one', async () => {
    const d = detector({ ...NYC, at: NOW - HOUR })
    expect(await evaluate(d, undefined)).toEqual([])
    expect(await evaluate(d, { country: 'JP' })).toEqual([])
    expect(await evaluate(d, { lat: TOKYO.lat })).toEqual([])
  })

  it('an identity with no last-seen', async () => {
    expect(await evaluate(detector(null), TOKYO)).toEqual([])
  })

  it('coordinates that are not a place on earth, on either side', async () => {
    const d = detector({ ...NYC, at: NOW - HOUR })
    for (const geo of [
      { lat: 91, lon: 0 },
      { lat: 0, lon: -181 },
      { lat: Number.NaN, lon: 0 },
    ]) {
      expect(await evaluate(d, geo)).toEqual([])
    }
    for (const stored of [
      { lat: 900, lon: 0 },
      { lat: Number.NaN, lon: 0 },
    ]) {
      expect(await evaluate(detector({ ...stored, at: NOW - HOUR }), TOKYO)).toEqual([])
    }
    for (const at of [Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(await evaluate(detector({ ...NYC, at }), TOKYO)).toEqual([])
    }
  })

  it('a request time that is not a number, which nothing upstream refuses', async () => {
    expect(await evaluate(detector({ ...NYC, at: NOW - HOUR }), TOKYO, Number.NaN)).toEqual([])
  })

  it('an identical position, however short the gap', async () => {
    expect(await evaluate(detector({ ...NYC, at: NOW - 1 }), NYC)).toEqual([])
  })

  it('a step across the antimeridian, which is a short distance and not half the planet', async () => {
    expect(await evaluate(detector({ at: NOW - HOUR, lat: 0, lon: 179.5 }), { lat: 0, lon: -179.5 })).toEqual([])
  })

  it('but a zero coordinate is a real place, not a missing one', async () => {
    expect(await evaluate(detector({ at: NOW - HOUR, lat: 0, lon: 0 }), TOKYO)).toMatchObject([
      { kind: 'impossible-travel' },
    ])
  })
})

describe('construction and the store', () => {
  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])('refuses a maxKmPerHour of %o', (maxKmPerHour) => {
    expect(() => detector(null, { maxKmPerHour })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])('refuses a minElapsedMs of %o', (minElapsedMs) => {
    // Zero is the divisor, so the most extreme teleport became an infinite speed and was discarded.
    expect(() => detector(null, { minElapsedMs })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('reads an explicit undefined as omitted, so the defaults apply', async () => {
    const d = detector({ ...NYC, at: NOW - 1 }, { maxKmPerHour: undefined, minElapsedMs: undefined })
    expect(await evaluate(d, TOKYO)).toMatchObject([{ evidence: { intervalMs: 60_000, threshold: 900 } }])
  })

  it('lets a getLastSeen that throws propagate, since the facet is what contains it', async () => {
    const d = authImpossibleTravelDetector({
      getLastSeen: async () => {
        throw new Error('store down')
      },
    })
    await expect(evaluate(d, TOKYO)).rejects.toThrow('store down')
  })
})
