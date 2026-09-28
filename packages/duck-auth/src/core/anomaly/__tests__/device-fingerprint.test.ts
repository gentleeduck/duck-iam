import { describe, expect, it, vi } from 'vitest'
import { sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { FINGERPRINT_ABSENT, FINGERPRINT_UNPARSED } from '../anomaly.constants'
import { AnomalyFacet } from '../anomaly.facet'
import type { Anomaly, AuthDeviceFingerprint } from '../anomaly.types'
import {
  AuthMemoryDeviceFingerprintStore,
  authMemoryDeviceFingerprintStore,
  deviceFingerprintDetector,
} from '../device-fingerprint.detector'

const UA = 'Mozilla/5.0 (Macintosh) Safari/605'
const HOME = { ip: '203.0.113.9', userAgent: UA }

/** Echoes what it hashes, so a test can read which device a request was bucketed as. */
const echo = (s: string) => `sha(${s})`

const ctx = (req: Partial<Anomaly.RequestSnapshot> = HOME, identityId = 'u1'): Anomaly.Context => ({
  identity: makeIdentity({ id: identityId }),
  req: { now: 1_760_000_000_000, ...req },
  session: makeSession(),
})

/** One request as the facet runs it: scored, then recorded under `decision`. */
async function sight(d: Anomaly.Detector, c: Anomaly.Context = ctx(), decision: Anomaly.Decision = 'allow') {
  const signals = await d.evaluate(c)
  await d.record?.(c, decision)
  return signals
}

const detector = (over: Partial<AuthDeviceFingerprint.Cfg> = {}) =>
  deviceFingerprintDetector({ authSha256: echo, store: new AuthMemoryDeviceFingerprintStore(), ...over })

/** The fingerprint each request is bucketed as, in order. */
async function buckets(...reqs: Partial<Anomaly.RequestSnapshot>[]): Promise<unknown[]> {
  const d = detector()
  return Promise.all(reqs.map(async (req) => (await d.evaluate(ctx(req)))[0]?.evidence.fingerprint))
}

describe('first sight', () => {
  it('is flagged at the default score, and nothing after it', async () => {
    const d = detector()
    expect(await sight(d)).toEqual([
      { evidence: { fingerprint: `sha(${UA}|203.0.113.0)` }, kind: 'new-device', score: 0.7 },
    ])
    expect(await sight(d)).toEqual([])
  })

  it('stores sha256 of the user agent and the /24, and nothing else, since that is what is compared later', async () => {
    const d = deviceFingerprintDetector({ authSha256: sha256, store: new AuthMemoryDeviceFingerprintStore() })
    expect((await d.evaluate(ctx()))[0]?.evidence).toEqual({ fingerprint: sha256(`${UA}|203.0.113.0`) })
    expect((await d.evaluate(ctx({})))[0]?.evidence).toEqual({
      fingerprint: sha256(`${FINGERPRINT_ABSENT}|${FINGERPRINT_ABSENT}`),
    })
  })

  it('scores at the configured score', async () => {
    expect(await sight(detector({ score: 0.95 }))).toMatchObject([{ score: 0.95 }])
  })

  it('keeps identities apart', async () => {
    const d = detector()
    await sight(d, ctx(HOME, 'u1'))
    expect(await sight(d, ctx(HOME, 'u2'))).toHaveLength(1)
  })

  it('a different user agent is a different device', async () => {
    const d = detector()
    await sight(d, ctx({ ...HOME, userAgent: 'Chrome/120' }))
    expect(await sight(d, ctx({ ...HOME, userAgent: 'Safari/17' }))).toHaveLength(1)
  })

  it('buckets a missing or blank user agent together, rather than going quiet', async () => {
    const [none, blank, bare] = await buckets({ ip: HOME.ip }, { ip: HOME.ip, userAgent: '   ' }, {})
    expect(none).toBe(`sha(${FINGERPRINT_ABSENT}|203.0.113.0)`)
    expect(blank).toBe(none)
    expect(bare).toBe(`sha(${FINGERPRINT_ABSENT}|${FINGERPRINT_ABSENT})`)
  })

  it('truncates an over-long user agent, so padding can neither switch it off nor mint a device', async () => {
    const [a, b] = await buckets({ ...HOME, userAgent: 'x'.repeat(1025) }, { ...HOME, userAgent: 'x'.repeat(2048) })
    expect(a).toBe(`sha(${'x'.repeat(1024)}|203.0.113.0)`)
    expect(b).toBe(a)
  })
})

describe('the address is reduced to the network it came from', () => {
  it.each([
    ['a copied user agent from the same /24', '203.0.113.9', '203.0.113.254'],
    ['a zero-padded ipv4', '203.0.113.9', '203.000.113.009'],
    ['a dual-stack ipv4', '192.0.2.7', '::ffff:192.0.2.9'],
    ['ipv6 in the same /48, however it is written', '2001:0db8:0000:0001::1', '2001:DB8::abcd'],
    ['a leading or trailing ::', '::1', '::2'],
    ['a /48 given in full or compressed', '2001:db8:1::', '2001:db8:1:ffff:0:0:0:1'],
  ])('reads %s as the same device', async (_, first, second) => {
    const [a, b] = await buckets({ ip: first, userAgent: UA }, { ip: second, userAgent: UA })
    expect(a).not.toContain(FINGERPRINT_UNPARSED)
    expect(b).toBe(a)
  })

  it.each([
    ['a different /24', '203.0.113.9', '203.0.114.9'],
    ['a different /48', '2001:db8:1::1', '2001:db8:2::1'],
    ['a dual-stack ipv4 in a different /24', '::ffff:192.0.2.7', '::ffff:198.51.100.9'],
  ])('reads %s as a new device', async (_, first, second) => {
    const [a, b] = await buckets({ ip: first, userAgent: UA }, { ip: second, userAgent: UA })
    expect(b).not.toBe(a)
  })

  it('collapses every address it cannot parse into one bucket, so junk cannot mint a device per request', async () => {
    const junk = [
      'not-an-ip',
      '999.1.1.1',
      '1.2.3',
      '1.2.3.4.5',
      '1::2::3',
      '1:2:3:4:5:6:7:8::9',
      'g:0:0:0:0:0:0:0',
      'a'.repeat(65),
    ]
    const seen = await buckets(...junk.map((ip) => ({ ip, userAgent: UA })))
    expect(new Set(seen)).toEqual(new Set([`sha(${UA}|${FINGERPRINT_UNPARSED})`]))
  })
})

describe('a device is remembered only once the verdict lets it through', () => {
  it('evaluating alone remembers nothing', async () => {
    const d = detector()
    expect(await d.evaluate(ctx())).toHaveLength(1)
    expect(await d.evaluate(ctx())).toHaveLength(1)
  })

  it('a denied request leaves the device new, and an allowed one does not', async () => {
    const d = detector()
    expect(await sight(d, ctx(), 'deny')).toHaveLength(1)
    expect(await sight(d, ctx(), 'allow')).toHaveLength(1)
    expect(await sight(d)).toEqual([])
  })

  it('a step-up is remembered, since the default lets it through, and forget undoes it', async () => {
    const store = new AuthMemoryDeviceFingerprintStore()
    const d = detector({ store })
    const [signal] = await sight(d, ctx(), 'step-up')
    expect(await sight(d)).toEqual([])
    await store.forget('u1', String(signal?.evidence.fingerprint))
    expect(await sight(d)).toHaveLength(1)
  })

  it('forgetAll drops one identity without touching another', async () => {
    const store = new AuthMemoryDeviceFingerprintStore()
    const d = detector({ store })
    await sight(d, ctx(HOME, 'u1'))
    await sight(d, ctx(HOME, 'u2'))
    await store.forgetAll('u1')
    expect(await sight(d, ctx(HOME, 'u1'))).toHaveLength(1)
    expect(await sight(d, ctx(HOME, 'u2'))).toEqual([])
  })
})

describe('a composer of your own', () => {
  it('needs no hash, and a constant one flags each identity once', async () => {
    const d = deviceFingerprintDetector({ compose: () => 'constant', store: new AuthMemoryDeviceFingerprintStore() })
    expect(await sight(d, ctx({ ip: '203.0.113.9' }))).toHaveLength(1)
    expect(await sight(d, ctx({ ip: '198.51.100.1' }))).toEqual([])
  })

  it.each([null, ''])('answering %o skips the request: no signal, nothing remembered', async (fingerprint) => {
    const store = new AuthMemoryDeviceFingerprintStore()
    const remember = vi.spyOn(store, 'remember')
    const d = deviceFingerprintDetector({ compose: () => fingerprint, store })
    expect(await sight(d)).toEqual([])
    expect(remember).not.toHaveBeenCalled()
  })

  it('that throws propagates, since only the facet contains it', async () => {
    const d = deviceFingerprintDetector({
      compose: () => {
        throw new Error('composer bug')
      },
      store: new AuthMemoryDeviceFingerprintStore(),
    })
    await expect(sight(d)).rejects.toThrow('composer bug')
  })
})

describe('through the facet', () => {
  const DENY_NEW: Partial<Anomaly.Cfg> = { reactions: { 'new-device': { 'new-device': 'deny' } } }
  const risk: Anomaly.Detector = { evaluate: async () => [{ evidence: {}, kind: 'risky-asn', score: 0.9 }], id: 'risk' }

  function facetWith(cfg: Partial<Anomaly.Cfg>, ...extra: Anomaly.Detector[]): AnomalyFacet {
    const facet = new AnomalyFacet(new InMemoryEvents(), cfg)
    for (const d of [detector(), ...extra]) facet.register(d)
    return facet
  }

  /** One request, let through whatever its verdict, as a host overriding it would. */
  async function admitted(facet: AnomalyFacet): Promise<Anomaly.Result> {
    const result = await facet.evaluate(ctx())
    await result.admit()
    return result
  }

  it('a device denied once is denied again on the retry, even let through', async () => {
    const facet = facetWith(DENY_NEW)
    expect((await admitted(facet)).decision).toBe('deny')
    expect((await admitted(facet)).decision).toBe('deny')
  })

  it('a device stepped up and let through is known on the next request, and one refused is not', async () => {
    const facet = facetWith({})
    expect((await facet.evaluate(ctx())).decision).toBe('step-up')
    expect((await admitted(facet)).decision).toBe('step-up')
    expect((await facet.evaluate(ctx())).decision).toBe('allow')
  })

  it('a deny the device helped reach is not undone by retrying', async () => {
    const facet = facetWith({}, risk)
    expect(await admitted(facet)).toMatchObject({ decision: 'deny', score: 0.97 })
    expect(await admitted(facet)).toMatchObject({ decision: 'deny', score: 0.97 })
  })

  it('parallel first requests are all flagged, and none passes as known', async () => {
    const facet = facetWith(DENY_NEW)
    const results = await Promise.all(Array.from({ length: 8 }, () => admitted(facet)))
    expect(results.map((r) => r.decision)).toEqual(Array(8).fill('deny'))
  })
})

describe('construction', () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, -0.5, 1.5])('refuses a score of %s', (score) => {
    expect(() => detector({ score })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: expect.stringContaining('score must be a finite number in [0, 1]') },
      }),
    )
  })

  it('accepts a score of 0 and of 1', () => {
    expect(() => detector({ score: 0 })).not.toThrow()
    expect(() => detector({ score: 1 })).not.toThrow()
  })

  it('refuses a store without has and remember, which would throw on every request', () => {
    const partial = Object.assign(new AuthMemoryDeviceFingerprintStore(), { remember: undefined })
    expect(() => detector({ store: partial })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('refuses no composer and no hash, rather than registering and staying silent', () => {
    expect(() => deviceFingerprintDetector({ store: new AuthMemoryDeviceFingerprintStore() })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: expect.stringMatching(/authSha256/) } }),
    )
  })
})

describe('the memory store', () => {
  /** Remember `count` devices, then answer whether the first is still known. */
  async function oldestSurvived(store: AuthMemoryDeviceFingerprintStore, count: number): Promise<boolean> {
    for (let i = 0; i < count; i++) await store.remember('u1', `fp${i}`)
    expect(await store.has('u1', `fp${count - 1}`)).toBe(true)
    return store.has('u1', 'fp0')
  }

  it('keeps 50 devices per identity by default, evicting past that', async () => {
    expect(await oldestSurvived(authMemoryDeviceFingerprintStore(), 50)).toBe(true)
    expect(await oldestSurvived(authMemoryDeviceFingerprintStore(), 51)).toBe(false)
  })

  it('takes its bounds through the factory', async () => {
    expect(await oldestSurvived(authMemoryDeviceFingerprintStore({ maxPerIdentity: 2 }), 2)).toBe(true)
    expect(await oldestSurvived(authMemoryDeviceFingerprintStore({ maxPerIdentity: 2 }), 3)).toBe(false)
  })

  it('evicts the least recently seen, not the first inserted', async () => {
    const store = new AuthMemoryDeviceFingerprintStore({ maxPerIdentity: 2 })
    for (const fp of ['daily', 'once', 'daily', 'new']) await store.remember('u1', fp)
    expect(await store.has('u1', 'daily')).toBe(true)
    expect(await store.has('u1', 'once')).toBe(false)
  })

  it('answers has without remembering, per identity', async () => {
    const store = new AuthMemoryDeviceFingerprintStore()
    expect(await store.has('u1', 'a')).toBe(false)
    expect(await store.has('u1', 'a')).toBe(false)
    await store.remember('u1', 'a')
    expect(await store.has('u1', 'a')).toBe(true)
    expect(await store.has('u2', 'a')).toBe(false)
  })

  it('expires a sighting past the ttl, and not a moment before', async () => {
    vi.useFakeTimers()
    try {
      const store = new AuthMemoryDeviceFingerprintStore({ ttlMs: 60_000 })
      await store.remember('u1', 'a')
      vi.advanceTimersByTime(60_000)
      expect(await store.has('u1', 'a')).toBe(true)
      vi.advanceTimersByTime(1)
      expect(await store.has('u1', 'a')).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it.each([
    ['maxPerIdentity', Number.NaN],
    ['maxPerIdentity', 0],
    ['maxPerIdentity', -1],
    ['ttlMs', Number.NaN],
    ['ttlMs', Number.POSITIVE_INFINITY],
    ['ttlMs', 0],
  ])('refuses a %s of %o, naming it', (key, value) => {
    expect(() => new AuthMemoryDeviceFingerprintStore({ [key]: value })).toThrow(
      expect.objectContaining({
        meta: { detail: expect.stringContaining(`${key} must be a finite positive number (got ${value})`) },
      }),
    )
  })
})
