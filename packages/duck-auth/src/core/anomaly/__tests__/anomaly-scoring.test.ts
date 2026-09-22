/**
 * The anomaly facet is a scoring aggregator, and an aggregator is attacked from
 * two sides: by the request (shape the inputs so no detector fires) and by the
 * detectors themselves (a plugin whose output steers the sum). The existing
 * suites cover the happy ladder and garbage signal shapes. These cover the
 * arithmetic and the exemptions, which is where a bypass hides.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Anomaly } from '~/core/anomaly/anomaly.types'
import { InMemoryEvents } from '~/core/events'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { AnomalyFacet } from '../anomaly.facet'
import { AuthMemoryDeviceFingerprintStore, deviceFingerprintDetector } from '../device-fingerprint.detector'
import { authImpossibleTravelDetector } from '../impossible-travel.detector'

const identity = makeIdentity({ id: 'u' })
const session = makeSession({ id: 'sid', identityId: 'u' })

const NOW = 1_760_000_000_000
const NYC = { lat: 40.7128, lon: -74.006 }
const TOKYO = { lat: 35.6762, lon: 139.6503 }

function signalOf(kind: Anomaly.Kind, score: number): Anomaly.Signal {
  return { evidence: {}, kind, score }
}

/** A detector whose entire output is chosen by the caller. */
function detectorOf(id: string, signals: Anomaly.Signal[]): Anomaly.Detector {
  return { evaluate: async () => signals, id }
}

function makeFacet(cfg: Partial<Anomaly.Cfg> = {}) {
  const events = new InMemoryEvents()
  const emitted: Array<{ score: number; signal: string }> = []
  events.on('suspicious', (payload) => {
    emitted.push(payload as never)
  })
  return { emitted, facet: new AnomalyFacet(events, cfg) }
}

const run = (facet: AnomalyFacet, req: Partial<Anomaly.RequestSnapshot> = {}) =>
  facet.evaluate({ identity, req: { now: NOW, ...req }, session })

describe('the aggregate saturates, so it cannot be steered by count or by sign', () => {
  it('a negative score is clamped away rather than vetoing another detector', async () => {
    const { facet, emitted } = makeFacet({ denyAt: 0.95, stepUpAt: 0.7, threshold: 0.7 })
    facet.register(detectorOf('honest', [signalOf('impossible-travel', 1)]))
    facet.register(detectorOf('hostile', [signalOf('new-device', -5)]))

    const result = await run(facet)
    expect(result.score).toBe(1)
    expect(result.decision).toBe('deny')
    expect(emitted).toHaveLength(1)
  })

  it('a score above one is clamped too, so it cannot outrun the ladder', async () => {
    const { facet } = makeFacet({ denyAt: 0.95, stepUpAt: 0.7 })
    facet.register(detectorOf('a', [signalOf('new-device', 50)]))
    expect((await run(facet)).score).toBe(1)
  })

  it('many weak signals saturate instead of summing into a deny nothing asked for', async () => {
    const { facet } = makeFacet()
    for (let i = 0; i < 5; i++) facet.register(detectorOf(`d${i}`, [signalOf('off-hours', 0.2)]))
    // 1 - 0.8^5 = 0.67232, under stepUpAt. A plain sum made this 1.0 and a deny.
    const result = await run(facet)
    expect(result.score).toBe(0.67232)
    expect(result.decision).toBe('allow')
  })

  it('but enough strong signals still reach deny', async () => {
    const { facet } = makeFacet()
    for (let i = 0; i < 4; i++) facet.register(detectorOf(`d${i}`, [signalOf('off-hours', 0.6)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('refuses a second detector under an id already registered', async () => {
    const { facet } = makeFacet()
    const d = detectorOf('new-device', [signalOf('new-device', 0.5)])
    facet.register(d)
    expect(() => facet.register(d)).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))

    expect(facet.list()).toEqual(['new-device'])
    expect((await run(facet)).score).toBe(0.5)
  })

  it('a reload path unregisters first, and then the id is free again', async () => {
    const { facet } = makeFacet()
    facet.register(detectorOf('new-device', [signalOf('new-device', 0.5)]))
    expect(facet.unregister('new-device')).toBe(true)
    expect(() => facet.register(detectorOf('new-device', [signalOf('new-device', 0.5)]))).not.toThrow()
    expect(facet.list()).toEqual(['new-device'])
  })

  it('a single signal at exactly denyAt denies', async () => {
    const { facet } = makeFacet({ denyAt: 0.95 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.95)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('a signal just under stepUpAt allows', async () => {
    const { facet } = makeFacet({ stepUpAt: 0.7 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.6999)]))
    expect((await run(facet)).decision).toBe('allow')
  })

  it('no detectors at all is an allow with no event', async () => {
    const { facet, emitted } = makeFacet()
    expect(await run(facet)).toEqual({ decision: 'allow', score: 0, signals: [] })
    expect(emitted).toHaveLength(0)
  })

  it('a detector emitting an empty array does not emit an event at threshold zero', async () => {
    // `signals.length > 0` guards the emit, so a zero threshold does not turn
    // every clean request into a suspicious record.
    const { facet, emitted } = makeFacet({ threshold: 0 })
    facet.register(detectorOf('a', []))
    await run(facet)
    expect(emitted).toHaveLength(0)
  })
})

describe('the event and the decision are computed separately', () => {
  it('records a NaN-driven deny, even though the score it reports is zero', async () => {
    const { facet, emitted } = makeFacet()
    facet.register(detectorOf('a', [signalOf('impossible-travel', Number.NaN)]))

    const result = await run(facet)
    expect(result.decision).toBe('deny')
    expect(result.score).toBe(0)
    expect(emitted).toHaveLength(1)
    expect(emitted[0]).toMatchObject({ meta: { decision: 'deny' } })
  })

  it('records a step-up that a raised event threshold would otherwise have hidden', async () => {
    const { facet, emitted } = makeFacet({ denyAt: 0.95, stepUpAt: 0.5, threshold: 0.9 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.6)]))

    expect((await run(facet)).decision).toBe('step-up')
    expect(emitted).toHaveLength(1)
  })

  it('records a deny that came from a reaction override rather than from the score', async () => {
    const { facet, emitted } = makeFacet({ reactions: { 'new-device': 'deny' } })
    facet.register(detectorOf('a', [signalOf('new-device', 0.01)]))

    expect((await run(facet)).decision).toBe('deny')
    expect(emitted).toHaveLength(1)
    expect(emitted[0]).toMatchObject({ meta: { decision: 'deny' }, score: 0.01 })
  })

  it('the emitted event names every contributing signal kind', async () => {
    const { facet, emitted } = makeFacet({ threshold: 0.5 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.4), signalOf('off-hours', 0.4)]))
    await run(facet)
    expect(emitted[0]).toMatchObject({ score: 0.64, signal: 'new-device+off-hours' })
  })

  it('names the identity the request actually carried, empty id included', async () => {
    const { facet, emitted } = makeFacet({ threshold: 0.1 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.5)]))
    await facet.evaluate({ identity: makeIdentity({ id: '' }), req: { now: NOW }, session })
    expect(emitted[0]).toHaveProperty('identityId', '')
  })
})

describe('per-kind reactions can raise but not lower', () => {
  it('an allow override mutes that signal, and only that signal', async () => {
    const { facet } = makeFacet({ reactions: { 'new-device': 'allow' }, stepUpAt: 0.7 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.8)]))
    const muted = await run(facet)
    expect(muted.score).toBe(0)
    expect(muted.decision).toBe('allow')

    // A detector that was not muted still scores and still raises the ladder.
    facet.register(detectorOf('b', [signalOf('off-hours', 0.8)]))
    expect((await run(facet)).decision).toBe('step-up')
  })

  it('a step-up override fires on a signal far below stepUpAt', async () => {
    const { facet } = makeFacet({ reactions: { 'impossible-travel': 'step-up' }, stepUpAt: 0.7 })
    facet.register(detectorOf('a', [signalOf('impossible-travel', 0.01)]))
    expect((await run(facet)).decision).toBe('step-up')
  })

  it('a score at denyAt outranks a step-up override', async () => {
    const { facet } = makeFacet({ denyAt: 0.95, reactions: { 'new-device': 'step-up' } })
    facet.register(detectorOf('a', [signalOf('new-device', 0.99)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('the strongest override across present kinds wins', async () => {
    const { facet } = makeFacet({ reactions: { 'new-device': 'step-up', 'off-hours': 'deny' } })
    facet.register(detectorOf('a', [signalOf('new-device', 0.01), signalOf('off-hours', 0.01)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('an override for a kind that did not fire is ignored', async () => {
    const { facet } = makeFacet({ reactions: { 'impossible-travel': 'deny' } })
    facet.register(detectorOf('a', [signalOf('new-device', 0.01)]))
    expect((await run(facet)).decision).toBe('allow')
  })

  it('a reaction can be scoped to the detector that earned it, so a plugin cannot claim it', async () => {
    // `isValidSignal` deliberately accepts kinds outside the union so plugins can extend it, and a
    // bare key still applies to whoever names that kind. The scoped key is the remedy.
    const impostor = () =>
      detectorOf('impostor', [{ evidence: {}, kind: 'impossible-travel', score: 0 } as Anomaly.Signal])

    const bare = makeFacet({ reactions: { 'impossible-travel': 'deny' } })
    bare.facet.register(impostor())
    expect((await run(bare.facet)).decision).toBe('deny')

    const scoped = makeFacet({ reactions: { 'travel.detector#impossible-travel': 'deny' } })
    scoped.facet.register(impostor())
    expect((await run(scoped.facet)).decision).toBe('allow')

    scoped.facet.register(
      detectorOf('travel.detector', [{ evidence: {}, kind: 'impossible-travel', score: 0 } as Anomaly.Signal]),
    )
    expect((await run(scoped.facet)).decision).toBe('deny')
  })

  it('stamps every accepted signal with the detector that produced it', async () => {
    const { facet } = makeFacet()
    facet.register(detectorOf('travel.detector', [signalOf('impossible-travel', 0.1)]))
    expect((await run(facet)).signals[0]).toMatchObject({ source: 'travel.detector' })
  })
})

describe('a misbehaving detector must not take authentication with it', () => {
  it('a throwing detector is skipped and the rest still score', async () => {
    const { facet } = makeFacet()
    facet.register({
      evaluate: async () => {
        throw new Error('boom')
      },
      id: 'bad',
    })
    facet.register(detectorOf('good', [signalOf('new-device', 0.5)]))
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    expect((await run(facet)).score).toBe(0.5)
    vi.restoreAllMocks()
  })

  it('a detector rejecting with a non-Error is also contained', async () => {
    const { facet } = makeFacet()
    facet.register({ evaluate: async () => Promise.reject('a string'), id: 'bad' })
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    await expect(run(facet)).resolves.toMatchObject({ decision: 'allow' })
    vi.restoreAllMocks()
  })

  it('runs detectors concurrently, so their latencies overlap rather than add', async () => {
    const { facet } = makeFacet()
    const order: string[] = []
    for (const id of ['a', 'b', 'c']) {
      facet.register({
        evaluate: async () => {
          order.push(`start-${id}`)
          await new Promise((r) => setTimeout(r, 5))
          order.push(`end-${id}`)
          return []
        },
        id,
      })
    }
    await run(facet)
    expect(order.slice(0, 3)).toEqual(['start-a', 'start-b', 'start-c'])
  })

  it('abandons a detector that overruns its timeout, and scores the rest', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const { facet } = makeFacet({ detectorTimeoutMs: 10, threshold: 0.4 })
    facet.register({ evaluate: () => new Promise(() => undefined), id: 'hangs' })
    facet.register(detectorOf('fast', [signalOf('new-device', 0.5)]))

    const started = Date.now()
    const result = await run(facet)
    expect(Date.now() - started).toBeLessThan(200)
    expect(result.score).toBe(0.5)
    expect(result.signals.map((s) => s.source)).toEqual(['fast'])
    vi.restoreAllMocks()
  })

  it('hands every detector a frozen snapshot, so none can edit what the others read', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const { facet } = makeFacet()
    facet.register({
      evaluate: async ({ req }) => {
        ;(req as { ip?: string }).ip = undefined
        return []
      },
      id: 'mutator',
    })
    let observed: string | undefined = 'unset'
    facet.register({
      evaluate: async ({ req }) => {
        observed = req.ip
        return []
      },
      id: 'observer',
    })
    await run(facet, { geo: { country: 'FR' }, ip: '203.0.113.9' })
    expect(observed).toBe('203.0.113.9')
    vi.restoreAllMocks()
  })

  it('a signal whose evidence is missing is still counted', async () => {
    const { facet } = makeFacet()
    facet.register(detectorOf('a', [{ kind: 'new-device', score: 0.5 } as Anomaly.Signal]))
    expect((await run(facet)).score).toBe(0.5)
  })

  it('a signal carrying a huge evidence blob is passed through untouched', async () => {
    // Worth pinning: nothing clips evidence before it reaches the event bus, so
    // whatever a detector attaches is what a log sink receives.
    const { facet, emitted } = makeFacet({ threshold: 0.1 })
    const blob = 'x'.repeat(200_000)
    facet.register(detectorOf('a', [{ evidence: { blob }, kind: 'new-device', score: 0.5 }]))
    await run(facet)
    expect((emitted[0] as unknown as { meta: { signals: Anomaly.Signal[] } }).meta.signals[0]?.evidence).toEqual({
      blob,
    })
  })
})

describe('impossible travel: what the detector agrees not to look at', () => {
  const detector = (last: { at: number; lat: number; lon: number } | null, config = {}) =>
    authImpossibleTravelDetector({ config, getLastSeen: async () => last })

  const evaluate = (d: Anomaly.Detector, geo: Anomaly.RequestSnapshot['geo'], now = NOW) =>
    d.evaluate({ identity, req: { geo, now }, session })

  it('flags a hop that is too fast to be travel', async () => {
    const d = detector({ ...NYC, at: NOW - 30 * 60_000 })
    const [signal] = await evaluate(d, TOKYO)
    expect(signal?.kind).toBe('impossible-travel')
    expect(signal?.score).toBe(1)
  })

  it('treats the minimum window as a floor on the interval, not as an exemption', async () => {
    const quick = detector({ ...NYC, at: NOW - 50_000 })
    expect((await evaluate(quick, TOKYO))[0]?.score).toBe(1)

    const slower = detector({ ...NYC, at: NOW - 70_000 })
    expect((await evaluate(slower, TOKYO))[0]?.score).toBe(1)
  })

  it('still forgives a short hop inside the window, which is what the floor is for', async () => {
    // Five km in ten seconds is NAT mobility, and dividing it by ten seconds would call it 1800
    // km/h. Divided by the 60s floor it is 300 km/h and no signal.
    const d = detector({ ...NYC, at: NOW - 10_000 })
    expect(await evaluate(d, { lat: NYC.lat + 0.045, lon: NYC.lon })).toEqual([])
  })

  it('does not let a last-seen stamp in the future read as a long gap', async () => {
    // Where last-seen is written from a client-supplied clock, tomorrow's date used to turn the
    // detector off: the elapsed time was absolute, so a day in the future was a day of travel.
    const d = detector({ ...NYC, at: NOW + 86_400_000 })
    expect((await evaluate(d, TOKYO))[0]?.score).toBe(1)
  })

  it('skips coordinates that are not a place on earth, on either side of the comparison', async () => {
    const d = detector({ ...NYC, at: NOW - 3_600_000 })
    for (const geo of [
      { lat: 900, lon: 4000 },
      { lat: 91, lon: 0 },
      { lat: 0, lon: -181 },
    ]) {
      expect(await evaluate(d, geo)).toEqual([])
    }
    const stored = detector({ at: NOW - 3_600_000, lat: 900, lon: 0 })
    expect(await evaluate(stored, TOKYO)).toEqual([])
  })

  it('scores from half a point upward the moment the limit is crossed', async () => {
    // The old curve was `(speed / max) - 1`, so crossing the limit was worth almost nothing and a
    // sustained 1500 km/h still decided allow.
    const d = detector({ ...NYC, at: NOW - 3_600_000 }, { maxKmPerHour: 900 })
    // 1000 km due east of New York, covered in one hour: a plausible ground speed, so a mild score.
    const [mild] = await evaluate(d, { lat: NYC.lat, lon: NYC.lon + 11.8 })
    expect(mild?.score).toBeGreaterThan(0.5)
    expect(mild?.score).toBeLessThan(0.6)

    // 1500 km in the same hour is not a person travelling, and now says so.
    const { facet } = makeFacet()
    facet.register(detector({ ...NYC, at: NOW - 3_600_000 }))
    const result = await facet.evaluate({
      identity,
      req: { geo: { lat: NYC.lat, lon: NYC.lon + 17.7 }, now: NOW },
      session,
    })
    expect(result.decision).toBe('step-up')
  })

  it('a zero coordinate is a real place, not a missing one', async () => {
    const d = detector({ at: NOW - 3_600_000, lat: 0, lon: 0 })
    const [signal] = await evaluate(d, TOKYO)
    expect(signal?.kind).toBe('impossible-travel')
  })

  it('an identical position produces no signal however short the gap', async () => {
    const d = detector({ ...NYC, at: NOW - 3_600_000 })
    expect(await evaluate(d, NYC)).toEqual([])
  })

  it('a longitude wrap across the antimeridian is a short distance, not half the planet', async () => {
    const d = detector({ at: NOW - 3_600_000, lat: 0, lon: 179.5 })
    expect(await evaluate(d, { lat: 0, lon: -179.5 })).toEqual([])
  })

  it('a NaN coordinate on the request is skipped rather than scored', async () => {
    const d = detector({ ...NYC, at: NOW - 3_600_000 })
    expect(await evaluate(d, { lat: Number.NaN, lon: 0 })).toEqual([])
  })

  it('a NaN coordinate in storage is skipped rather than scored', async () => {
    const d = detector({ at: NOW - 3_600_000, lat: Number.NaN, lon: 0 })
    expect(await evaluate(d, TOKYO)).toEqual([])
  })

  it('a getLastSeen that throws propagates out of the detector', async () => {
    // Pinned because the facet is what contains it; the detector itself does not.
    const d = authImpossibleTravelDetector({
      getLastSeen: async () => {
        throw new Error('store down')
      },
    })
    await expect(evaluate(d, TOKYO)).rejects.toThrow('store down')
  })

  it('refuses a non-positive speed limit at construction', () => {
    expect(() => authImpossibleTravelDetector({ config: { maxKmPerHour: 0 }, getLastSeen: async () => null })).toThrow()
    expect(() =>
      authImpossibleTravelDetector({ config: { maxKmPerHour: -1 }, getLastSeen: async () => null }),
    ).toThrow()
  })

  it('refuses a non-positive minimum interval at construction', () => {
    // Zero is what the speed is divided by, so it turned the most extreme possible teleport into an
    // infinite speed that the finite check then discarded.
    for (const minElapsedMs of [0, -1, Number.NaN]) {
      expect(() => detector(null, { minElapsedMs })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
  })

  it('two samples at the same instant are the floor interval, and a teleport across them scores', async () => {
    const d = detector({ ...NYC, at: NOW })
    expect((await evaluate(d, TOKYO))[0]?.score).toBe(1)
  })

  it('reports the raw signed elapsed time in evidence, not the absolute one used for the maths', async () => {
    const d = detector({ ...NYC, at: NOW + 60_000 }, { maxKmPerHour: 1 })
    const [signal] = await evaluate(d, TOKYO)
    expect(signal?.evidence.elapsedMs).toBe(-60_000)
  })
})

describe('device fingerprint: what counts as the same device', () => {
  const sha = (s: string) => `sha(${s})`
  const make = (over: Partial<Parameters<typeof deviceFingerprintDetector>[0]> = {}) => {
    const store = new AuthMemoryDeviceFingerprintStore()
    return { detector: deviceFingerprintDetector({ authSha256: sha, store, ...over }), store }
  }
  const seen = (d: Anomaly.Detector, req: Partial<Anomaly.RequestSnapshot>) =>
    d.evaluate({ identity, req: { now: NOW, ...req }, session })

  const UA = 'Mozilla/5.0 (Macintosh) Safari/605'

  it('flags a request that omits the user agent instead of going quiet', async () => {
    const { detector } = make()
    expect(await seen(detector, { ip: '203.0.113.9', userAgent: UA })).toHaveLength(1)
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: undefined })).toHaveLength(1)
    // A second header-less request from the same subnet is the same device, not a new one, so the
    // bucket is shared rather than one per sighting.
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: '   ' })).toEqual([])
  })

  it('truncates an over-long user agent rather than letting padding switch it off', async () => {
    const { detector } = make()
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: 'x'.repeat(1025) })).toHaveLength(1)
    // Same first 1024 characters, so the cap cannot be used to mint a second device either.
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: 'x'.repeat(2048) })).toEqual([])
  })

  it('lets an application undo a sighting it refused, so the retry is a new device again', async () => {
    const { detector, store } = make()
    const req = { ip: '203.0.113.9', userAgent: 'curl/8.4.0' }
    const [signal] = await seen(detector, req)
    expect(signal).toBeDefined()
    // Without the undo, the denied attempt had already whitelisted the fingerprint.
    expect(await seen(detector, req)).toEqual([])

    await store.forget('u', signal?.evidence.fingerprint as string)
    expect(await seen(detector, req)).toHaveLength(1)
  })

  it('caps what the memory store remembers per identity, evicting the oldest', async () => {
    const store = new AuthMemoryDeviceFingerprintStore({ maxPerIdentity: 3 })
    const d = deviceFingerprintDetector({ authSha256: sha, store })
    for (let i = 0; i < 2000; i++) await seen(d, { ip: '203.0.113.9', userAgent: `ua-${i}` })

    // The most recent three are still known; the first is not.
    expect(await seen(d, { ip: '203.0.113.9', userAgent: 'ua-1999' })).toEqual([])
    expect(await seen(d, { ip: '203.0.113.9', userAgent: 'ua-0' })).toHaveLength(1)
  })

  it('forgets a sighting older than the ttl', async () => {
    const store = new AuthMemoryDeviceFingerprintStore({ ttlMs: 1 })
    const d = deviceFingerprintDetector({ authSha256: sha, store })
    const req = { ip: '203.0.113.9', userAgent: UA }
    expect(await seen(d, req)).toHaveLength(1)
    await new Promise((r) => setTimeout(r, 5))
    expect(await seen(d, req)).toHaveLength(1)
  })

  it('a copied user agent from the same /24 reads as the same device', async () => {
    // Deliberate roaming tolerance, pinned because it is the cost of it: an
    // attacker on the victim's network who echoes the browser string is known.
    const { detector } = make()
    await seen(detector, { ip: '203.0.113.9', userAgent: UA })
    expect(await seen(detector, { ip: '203.0.113.254', userAgent: UA })).toEqual([])
  })

  it('a different /24 is a new device', async () => {
    const { detector } = make()
    await seen(detector, { ip: '203.0.113.9', userAgent: UA })
    expect(await seen(detector, { ip: '203.0.114.9', userAgent: UA })).toHaveLength(1)
  })

  it('reads a zero-padded ipv4 as the same device as the address unpadded', async () => {
    const { detector } = make()
    await seen(detector, { ip: '203.0.113.9', userAgent: UA })
    expect(await seen(detector, { ip: '203.000.113.009', userAgent: UA })).toEqual([])
  })

  it('collapses ipv6 addresses in the same /48 whichever way they are written', async () => {
    const { detector } = make()
    await seen(detector, { ip: '2001:0db8:0000:0001::1', userAgent: UA })
    expect(await seen(detector, { ip: '2001:DB8::abcd', userAgent: UA })).toEqual([])
  })

  it('separates ipv6 addresses in different /48s', async () => {
    const { detector } = make()
    await seen(detector, { ip: '2001:db8:1::1', userAgent: UA })
    expect(await seen(detector, { ip: '2001:db8:2::1', userAgent: UA })).toHaveLength(1)
  })

  it('collapses every unparseable address into one bucket', async () => {
    // Junk used to be hashed as-is, so two junk values were two devices and a caller who controls
    // the ip could mint a `new-device` signal on demand.
    const { detector } = make()
    expect(await seen(detector, { ip: 'not-an-ip', userAgent: UA })).toHaveLength(1)
    expect(await seen(detector, { ip: 'also-not-an-ip', userAgent: UA })).toEqual([])
    expect(await seen(detector, { ip: '999.1.1.1', userAgent: UA })).toEqual([])
  })

  it('buckets an address longer than the guard allows rather than going quiet', async () => {
    const { detector } = make()
    expect(await seen(detector, { ip: 'a'.repeat(65), userAgent: UA })).toHaveLength(1)
  })

  it('still reduces a dual-stack ipv4 client to its /24, as stored fingerprints expect', async () => {
    const { detector } = make()
    expect(await seen(detector, { ip: '::ffff:192.0.2.7', userAgent: UA })).toHaveLength(1)
    expect(await seen(detector, { ip: '::ffff:192.0.2.9', userAgent: UA })).toEqual([])
    expect(await seen(detector, { ip: '::ffff:198.51.100.9', userAgent: UA })).toHaveLength(1)
  })

  it('is refused at construction when no hashing helper was supplied and no composer overrides it', () => {
    // This asserted `[]` - the detector built, registered, listed, and stayed silent on every request.
    // Its own neighbours here are named for the opposite rule ("rather than going quiet"): a request
    // that will not identify itself gets a shared bucket instead of switching the detector off.
    const store = new AuthMemoryDeviceFingerprintStore()
    expect(() => deviceFingerprintDetector({ store })).toThrowError(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('keeps the raw ip and user agent out of the evidence, and so out of the event', async () => {
    const { detector } = make()
    const [signal] = await seen(detector, { ip: '203.0.113.9', userAgent: UA })
    // Asserted on the keys, not on a substring: this suite's `authSha256` stub echoes its input, so
    // a substring check here would be checking the stub rather than the evidence.
    expect(Object.keys(signal?.evidence ?? {})).toEqual(['fingerprint'])
  })

  it('a custom composer returning the same value for every request never flags anyone twice', async () => {
    const store = new AuthMemoryDeviceFingerprintStore()
    const detector = deviceFingerprintDetector({ compose: () => 'constant', store })
    expect(await seen(detector, { ip: '203.0.113.9' })).toHaveLength(1)
    expect(await seen(detector, { ip: '198.51.100.1' })).toEqual([])
  })

  it('a composer that throws propagates, since only the facet contains it', async () => {
    const store = new AuthMemoryDeviceFingerprintStore()
    const detector = deviceFingerprintDetector({
      compose: () => {
        throw new Error('composer bug')
      },
      store,
    })
    await expect(seen(detector, { ip: '203.0.113.9' })).rejects.toThrow('composer bug')
  })

  it('forgetAll drops one identity without touching another', async () => {
    const { detector, store } = make()
    await seen(detector, { ip: '203.0.113.9', userAgent: UA })
    await detector.evaluate({
      identity: makeIdentity({ id: 'other' }),
      req: { ip: '203.0.113.9', now: NOW, userAgent: UA },
      session,
    })

    await store.forgetAll('u')
    expect(await seen(detector, { ip: '203.0.113.9', userAgent: UA })).toHaveLength(1)
    expect(
      await detector.evaluate({
        identity: makeIdentity({ id: 'other' }),
        req: { ip: '203.0.113.9', now: NOW, userAgent: UA },
        session,
      }),
    ).toEqual([])
  })

  it('concurrent first sights of the same device resolve to one signal', async () => {
    const { detector } = make()
    const results = await Promise.all(
      Array.from({ length: 8 }, () => seen(detector, { ip: '203.0.113.9', userAgent: UA })),
    )
    expect(results.filter((r) => r.length > 0)).toHaveLength(1)
  })
})

/**
 * `Signal.score` is documented as "0..1 ... clamped into that range on intake", and `evaluate`
 * clamps in `_runDetector`. `decide` is the other intake - documented as the same ladder, standalone,
 * for re-deciding on signals a caller kept - and it clamped nothing, so the noisy-or arithmetic ran on
 * numbers it is not defined over.
 */
describe('decide normalises the scores it is handed, like evaluate does', () => {
  it('a second equally-severe signal cannot lower the decision', () => {
    const facet = new AnomalyFacet(new InMemoryEvents())
    const one = facet.decide([signalOf('new-device', 1.5)])
    const two = facet.decide([signalOf('new-device', 1.5), signalOf('impossible-travel', 1.5)])

    expect(one).toBe('deny')
    expect(two).toBe('deny')
  })

  it('a score above 1 is worth exactly 1, not more', () => {
    const facet = new AnomalyFacet(new InMemoryEvents())
    // 0.5 with a clamped 1.0 saturates; unclamped, `1 - 4` made it 1 - (0.5 * -3) = 2.5, which still
    // denies - the direction only inverts once two out-of-range signals meet.
    expect(facet.decide([signalOf('new-device', 4), signalOf('impossible-travel', 0.5)])).toBe('deny')
  })

  it('a negative score is worth zero, not a discount on the others', () => {
    const facet = new AnomalyFacet(new InMemoryEvents())
    // Unclamped, `1 - (-9)` is 10: the remainder is multiplied by ten and the aggregate comes out at
    // -1, so one signal carrying a negative score *mutes* every real one beside it and the ladder
    // reports allow. That is the fail-open direction, and it needs one misbehaving detector.
    expect(facet.decide([signalOf('new-device', 0.8), signalOf('impossible-travel', -9)])).toBe('step-up')
  })

  it('evaluate and decide agree on the same signals', async () => {
    const facet = new AnomalyFacet(new InMemoryEvents())
    facet.register(detectorOf('d', [signalOf('new-device', 1.5), signalOf('impossible-travel', 1.5)]))
    const result = await facet.evaluate({ identity, req: { now: NOW }, session })

    expect(facet.decide(result.signals)).toBe(result.decision)
    expect(result.decision).toBe('deny')
  })
})
