/**
 * The anomaly facet is a scoring aggregator, and an aggregator is attacked from
 * two sides: by the request (shape the inputs so no detector fires) and by the
 * detectors themselves (a plugin whose output steers the sum). The existing
 * suites cover the happy ladder and garbage signal shapes. These cover the
 * arithmetic and the exemptions, which is where a bypass hides.
 *
 * Sources: OWASP ASVS V7 (logging and monitoring must record the decision that
 * was taken), NIST SP 800-63B section 5.2.2 on risk-based reauthentication, and
 * the general rule that an evasion is whatever the scorer is told to skip.
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

describe('the aggregate is a plain sum, and a sum can be steered', () => {
  it('FINDING: a negative score from one detector cancels a real signal from another', async () => {
    // `isValidSignal` accepts any finite number, and `sumScores` adds it as-is.
    // A detector that returns a negative score, whether buggy or hostile, is a
    // veto over every other detector: it subtracts from the aggregate until the
    // ladder reads `allow`. Scores are documented as 0..1 and never clamped.
    const { facet, emitted } = makeFacet({ denyAt: 0.95, stepUpAt: 0.7, threshold: 0.7 })
    facet.register(detectorOf('honest', [signalOf('impossible-travel', 1)]))
    facet.register(detectorOf('hostile', [signalOf('new-device', -5)]))

    const result = await run(facet)
    expect(result.score).toBe(-4)
    expect(result.decision).toBe('allow')
    expect(emitted).toHaveLength(0)
  })

  it('FINDING: many weak signals add up to a deny no single detector asked for', async () => {
    // Five detectors each reporting a mild 0.2 cross `denyAt` together. Summing
    // unbounded scores means the ladder is calibrated against the number of
    // registered detectors, not against their severity.
    const { facet } = makeFacet()
    for (let i = 0; i < 5; i++) facet.register(detectorOf(`d${i}`, [signalOf('off-hours', 0.2)]))
    expect((await run(facet)).decision).toBe('deny')
  })

  it('FINDING: registering the same detector twice counts it twice', async () => {
    // `register` appends without checking the id, so a module loaded twice, or a
    // plugin re-registering on reload, silently doubles that detector's weight.
    const { facet } = makeFacet()
    const d = detectorOf('new-device', [signalOf('new-device', 0.5)])
    facet.register(d)
    facet.register(d)

    expect(facet.list()).toEqual(['new-device', 'new-device'])
    expect((await run(facet)).score).toBe(1)
  })

  it('FINDING: unregister removes only the first detector holding an id', async () => {
    const { facet } = makeFacet()
    const d = detectorOf('new-device', [signalOf('new-device', 0.5)])
    facet.register(d)
    facet.register(d)
    facet.unregister('new-device')

    expect(facet.list()).toEqual(['new-device'])
    expect((await run(facet)).score).toBe(0.5)
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
  it('FINDING: a NaN score denies the request but emits no suspicious event', async () => {
    // `decide` fails closed on a non-finite score, which is right. But
    // `sumScores` skips the same signal, so the aggregate is 0, the threshold is
    // never crossed, and the strongest decision the facet can return is taken
    // with nothing written to the audit trail.
    const { facet, emitted } = makeFacet()
    facet.register(detectorOf('a', [signalOf('impossible-travel', Number.NaN)]))

    const result = await run(facet)
    expect(result.decision).toBe('deny')
    expect(result.score).toBe(0)
    expect(emitted).toHaveLength(0)
  })

  it('FINDING: a threshold above stepUpAt makes step-up decisions invisible to audit', async () => {
    // `threshold` gates the event and `stepUpAt` gates the decision, with no
    // relation enforced between them. An operator who raises the event threshold
    // to cut noise also blinds the log to every step-up it caused.
    const { facet, emitted } = makeFacet({ denyAt: 0.95, stepUpAt: 0.5, threshold: 0.9 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.6)]))

    expect((await run(facet)).decision).toBe('step-up')
    expect(emitted).toHaveLength(0)
  })

  it('FINDING: a reaction override denies without ever emitting an event', async () => {
    // The per-kind override bypasses the score entirely, so the loudest possible
    // outcome, deny on a single low-scoring signal, leaves no record at all.
    const { facet, emitted } = makeFacet({ reactions: { 'new-device': 'deny' } })
    facet.register(detectorOf('a', [signalOf('new-device', 0.01)]))

    expect((await run(facet)).decision).toBe('deny')
    expect(emitted).toHaveLength(0)
  })

  it('the emitted event names every contributing signal kind', async () => {
    const { facet, emitted } = makeFacet({ threshold: 0.5 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.4), signalOf('off-hours', 0.4)]))
    await run(facet)
    expect(emitted[0]).toMatchObject({ score: 0.8, signal: 'new-device+off-hours' })
  })

  it('FINDING: an empty identity id drops the identity from the event entirely', async () => {
    // The spread is guarded on truthiness, so an empty-string id produces a
    // suspicious record with no subject rather than one naming the empty id.
    const { facet, emitted } = makeFacet({ threshold: 0.1 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.5)]))
    await facet.evaluate({ identity: makeIdentity({ id: '' }), req: { now: NOW }, session })
    expect(emitted[0]).not.toHaveProperty('identityId')
  })
})

describe('per-kind reactions can raise but not lower', () => {
  it('FINDING: an explicit allow override cannot hold back a score-driven step-up', async () => {
    // `severity[kindDecision] > 0` means an `allow` override is indistinguishable
    // from no override, so an operator who writes `{ 'new-device': 'allow' }` to
    // stop a noisy detector forcing step-up gets step-up anyway.
    const { facet } = makeFacet({ reactions: { 'new-device': 'allow' }, stepUpAt: 0.7 })
    facet.register(detectorOf('a', [signalOf('new-device', 0.8)]))
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

  it('FINDING: a plugin can name its own kind and claim any reaction key', async () => {
    // `isValidSignal` deliberately accepts kinds outside the union so plugins can
    // extend it. Combined with reactions being keyed by that same free string, a
    // detector chooses which configured reaction applies to it by picking a kind,
    // including one the operator wrote for a different detector.
    const { facet } = makeFacet({ reactions: { 'impossible-travel': 'deny' } })
    facet.register(detectorOf('impostor', [{ evidence: {}, kind: 'impossible-travel', score: 0 } as Anomaly.Signal]))
    expect((await run(facet)).decision).toBe('deny')
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

  it('FINDING: detectors run one after another with no timeout, so one slow plugin stalls every sign-in', async () => {
    // The loop awaits each detector in turn. A detector that hangs on a network
    // call holds the request open indefinitely, and even well-behaved ones add
    // their latencies rather than overlapping.
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
    expect(order).toEqual(['start-a', 'end-a', 'start-b', 'end-b', 'start-c', 'end-c'])
  })

  it('FINDING: a detector can mutate the request snapshot the later detectors read', async () => {
    // The same object is handed to every detector, so the first one registered
    // decides what the rest see. A plugin can blank the ip and disable the
    // fingerprint detector that runs after it.
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
    await run(facet, { ip: '203.0.113.9' })
    expect(observed).toBeUndefined()
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

  it('FINDING: the same hop inside the minimum window is exempt entirely', async () => {
    // `minElapsedMs` defaults to 60s to forgive NAT mobility, but it is applied
    // before any distance check. Two sign-ins from opposite sides of the planet
    // fifty seconds apart, the least plausible pattern there is, produce no
    // signal at all, while the same pair seventy seconds apart scores 1.
    const quick = detector({ ...NYC, at: NOW - 50_000 })
    expect(await evaluate(quick, TOKYO)).toEqual([])

    const slower = detector({ ...NYC, at: NOW - 70_000 })
    expect((await evaluate(slower, TOKYO))[0]?.score).toBe(1)
  })

  it('FINDING: a last-seen timestamp in the future silences the detector', async () => {
    // Elapsed time is absolute to tolerate clock skew, so a future stamp reads as
    // a long gap and the speed comes out plausible. Wherever last-seen is written
    // from a client-supplied clock, writing tomorrow's date turns detection off.
    const d = detector({ ...NYC, at: NOW + 86_400_000 })
    expect(await evaluate(d, TOKYO)).toEqual([])
  })

  it('FINDING: coordinates outside the valid range are scored rather than rejected', async () => {
    // Only `Number.isFinite` is checked. A latitude of 900 is not a place, but
    // haversine returns a number for it, so the detector reports a distance and a
    // speed derived from nonsense.
    const d = detector({ ...NYC, at: NOW - 3_600_000 })
    const [signal] = await evaluate(d, { lat: 900, lon: 4000 })
    expect(signal).toBeDefined()
    expect(Number.isFinite(signal?.evidence.distanceKm as number)).toBe(true)
  })

  it('FINDING: the score is near zero for anything under twice the speed limit', async () => {
    // The score is `(speed / max) - 1`, so crossing the limit is worth almost
    // nothing and only a 2x overshoot reaches 1. With the default ladder a
    // sustained 1500 km/h, impossible for a person, still decides `allow`.
    const d = detector({ ...NYC, at: NOW - 3_600_000 }, { maxKmPerHour: 900 })
    // 1000 km due east of New York, covered in one hour.
    const [signal] = await evaluate(d, { lat: NYC.lat, lon: NYC.lon + 11.8 })
    expect(signal?.score).toBeLessThan(0.2)

    const { facet } = makeFacet()
    facet.register(detector({ ...NYC, at: NOW - 3_600_000 }))
    const result = await facet.evaluate({
      identity,
      req: { geo: { lat: NYC.lat, lon: NYC.lon + 11.8 }, now: NOW },
      session,
    })
    expect(result.decision).toBe('allow')
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

  it('FINDING: a zero minimum elapsed time makes any gap divide by an interval of zero', async () => {
    // `minElapsedMs: 0` is accepted with no validation. Two samples at the same
    // instant give an infinite speed, which the finite check then discards, so
    // the most extreme possible teleport is the one case that reports nothing.
    const d = detector({ ...NYC, at: NOW }, { minElapsedMs: 0 })
    expect(await evaluate(d, TOKYO)).toEqual([])
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

  it('FINDING: omitting the user agent turns the detector off instead of flagging it', async () => {
    // A request with no `User-Agent` cannot be fingerprinted, so the composer
    // returns null and no signal is emitted. Sending no header is entirely under
    // an attacker's control, and it is also the one thing no real browser does,
    // so the evasion is both free and the opposite of the signal it suppresses.
    const { detector } = make()
    expect(await seen(detector, { ip: '203.0.113.9', userAgent: UA })).toHaveLength(1)
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: undefined })).toEqual([])
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: '   ' })).toEqual([])
  })

  it('FINDING: an over-long user agent also silences the detector', async () => {
    // The 1024-character guard exists to bound the hash input, but it returns
    // null rather than truncating, so padding the header past the limit is a
    // second way to opt out of being fingerprinted.
    const { detector } = make()
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: 'x'.repeat(1025) })).toEqual([])
    expect(await seen(detector, { ip: '198.51.100.4', userAgent: 'x'.repeat(1024) })).toHaveLength(1)
  })

  it('FINDING: a flagged device is remembered, so the second attempt from it is silent', async () => {
    // `checkAndRemember` inserts on first sight regardless of what the caller
    // decides afterwards. A sign-in that the application denied on a `new-device`
    // signal has already whitelisted that fingerprint, and the retry passes
    // unremarked. There is no way to record a sighting conditionally.
    const { detector } = make()
    expect(await seen(detector, { ip: '203.0.113.9', userAgent: 'curl/8.4.0' })).toHaveLength(1)
    expect(await seen(detector, { ip: '203.0.113.9', userAgent: 'curl/8.4.0' })).toEqual([])
  })

  it('FINDING: the memory store keeps every fingerprint forever, with no cap and no expiry', async () => {
    // One request per rotated user agent grows the set without bound. It is the
    // reference implementation, but it is exported and it is what the default
    // wiring reaches for.
    const { detector, store } = make()
    for (let i = 0; i < 2000; i++) await seen(detector, { ip: '203.0.113.9', userAgent: `ua-${i}` })
    const known = (store as unknown as { _known: Map<string, Set<string>> })._known
    expect(known.get('u')?.size).toBe(2000)
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

  it('FINDING: a zero-padded ipv4 is a different device from the same address unpadded', async () => {
    // The subnet is taken by splitting on dots with no normalisation, so
    // `203.000.113.009` and `203.0.113.9` hash differently. A proxy that
    // normalises differently from the origin re-flags a known device.
    const { detector } = make()
    await seen(detector, { ip: '203.0.113.9', userAgent: UA })
    expect(await seen(detector, { ip: '203.000.113.009', userAgent: UA })).toHaveLength(1)
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

  it('FINDING: an unparseable address is fingerprinted as-is rather than refused', async () => {
    // `expandIpv6` returns its input when the shape is wrong, so junk in the ip
    // position becomes part of the key. Two different junk values are two
    // different devices, which is a way to force a `new-device` signal on demand
    // wherever the ip is taken from a header.
    const { detector } = make()
    expect(await seen(detector, { ip: 'not-an-ip', userAgent: UA })).toHaveLength(1)
    expect(await seen(detector, { ip: 'also-not-an-ip', userAgent: UA })).toHaveLength(1)
  })

  it('refuses an address longer than the guard allows', async () => {
    const { detector } = make()
    expect(await seen(detector, { ip: 'a'.repeat(65), userAgent: UA })).toEqual([])
  })

  it('emits nothing when no hashing helper was supplied and no composer overrides it', async () => {
    const store = new AuthMemoryDeviceFingerprintStore()
    const detector = deviceFingerprintDetector({ store })
    expect(await seen(detector, { ip: '203.0.113.9', userAgent: UA })).toEqual([])
  })

  it('FINDING: the evidence carries the raw ip and user agent into the event', async () => {
    // The fingerprint is a hash, but the values it was built from ride alongside
    // it, so a `suspicious` record contains the address and header verbatim
    // wherever the bus is persisted.
    const { detector } = make()
    const [signal] = await seen(detector, { ip: '203.0.113.9', userAgent: UA })
    expect(signal?.evidence).toMatchObject({ ip: '203.0.113.9', userAgent: UA })
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
