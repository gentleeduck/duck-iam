import { describe, expect, it, vi } from 'vitest'
import { sha256 } from '~/core/crypto'
import type { Session } from '~/core/sessions/sessions.types'
import type { Identity } from '~/core/identities/identities.types'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { AuthMemoryDeviceFingerprintStore, deviceFingerprintDetector } from '../device-fingerprint.detector'

function ctx(overrides: Partial<{ ip: string; userAgent: string; identityId: string }> = {}) {
  return {
    identity: makeIdentity({ id: overrides.identityId ?? 'u1' }),
    session: makeSession(),
    req: {
      ip: overrides.ip ?? '203.0.113.4',
      userAgent: overrides.userAgent ?? 'Mozilla/5.0',
      now: Date.now(),
    },
  }
}

describe('deviceFingerprintDetector', () => {
  it('emits new-device signal on first sight + nothing on repeats', async () => {
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      authSha256: sha256,
    })
    const first = await detector.evaluate(ctx())
    expect(first).toHaveLength(1)
    expect(first[0]!.kind).toBe('new-device')
    expect(first[0]!.score).toBeGreaterThan(0)

    const second = await detector.evaluate(ctx())
    expect(second).toEqual([])
  })

  it('different IP subnet flips the signal', async () => {
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      authSha256: sha256,
    })
    await detector.evaluate(ctx({ ip: '203.0.113.4' }))
    const moved = await detector.evaluate(ctx({ ip: '198.51.100.7' }))
    expect(moved).toHaveLength(1)
  })

  it('same /24 subnet does NOT flip the signal (coffee-shop roaming)', async () => {
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      authSha256: sha256,
    })
    await detector.evaluate(ctx({ ip: '203.0.113.4' }))
    const sameSubnet = await detector.evaluate(ctx({ ip: '203.0.113.99' }))
    expect(sameSubnet).toEqual([])
  })

  it('different user agent flips the signal', async () => {
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      authSha256: sha256,
    })
    await detector.evaluate(ctx({ userAgent: 'Chrome/120' }))
    const otherUa = await detector.evaluate(ctx({ userAgent: 'Safari/17' }))
    expect(otherUa).toHaveLength(1)
  })

  it('missing UA or IP -> no signal', async () => {
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      authSha256: sha256,
    })
    const result = await detector.evaluate({
      identity: makeIdentity({ id: 'u1' }),
      session: makeSession(),
      req: { now: Date.now() },
    })
    expect(result).toEqual([])
  })

  it('respects custom compose function', async () => {
    const compose = vi.fn(() => 'fixed-fingerprint')
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      compose,
    })
    await detector.evaluate(ctx())
    const second = await detector.evaluate(ctx({ ip: '1.2.3.4' }))
    // compose returns the same value both times -> known on 2nd call.
    expect(second).toEqual([])
    expect(compose).toHaveBeenCalledTimes(2)
  })

  it('respects custom score', async () => {
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      authSha256: sha256,
      score: 0.95,
    })
    const result = await detector.evaluate(ctx())
    expect(result[0]!.score).toBe(0.95)
  })

  it('forgetAll clears the store so next sighting fires again', async () => {
    const store = new AuthMemoryDeviceFingerprintStore()
    const detector = deviceFingerprintDetector({ store, authSha256: sha256 })
    await detector.evaluate(ctx())
    expect(await detector.evaluate(ctx())).toEqual([])
    await store.forgetAll('u1')
    expect(await detector.evaluate(ctx())).toHaveLength(1)
  })

  it('per-identity isolation: u1 first sight does not silence u2 first sight', async () => {
    const detector = deviceFingerprintDetector({
      store: new AuthMemoryDeviceFingerprintStore(),
      authSha256: sha256,
    })
    await detector.evaluate(ctx({ identityId: 'u1' }))
    const u2 = await detector.evaluate(ctx({ identityId: 'u2' }))
    expect(u2).toHaveLength(1)
  })

  describe('score config validation', () => {
    it('refuses construction with NaN score (would emit signals where `score > threshold` is silently `false`)', () => {
      expect(() =>
        deviceFingerprintDetector({
          store: new AuthMemoryDeviceFingerprintStore(),
          authSha256: sha256,
          score: Number.NaN,
        }),
      ).toThrow(/score must be a finite number/)
    })

    it('refuses construction with Infinity (would dominate any aggregate suspicious score)', () => {
      expect(() =>
        deviceFingerprintDetector({
          store: new AuthMemoryDeviceFingerprintStore(),
          authSha256: sha256,
          score: Number.POSITIVE_INFINITY,
        }),
      ).toThrow(/score must be a finite number/)
    })

    it('refuses negative score', () => {
      expect(() =>
        deviceFingerprintDetector({
          store: new AuthMemoryDeviceFingerprintStore(),
          authSha256: sha256,
          score: -0.5,
        }),
      ).toThrow(/score must be a finite number/)
    })

    it('refuses score > 1 (out-of-range)', () => {
      expect(() =>
        deviceFingerprintDetector({
          store: new AuthMemoryDeviceFingerprintStore(),
          authSha256: sha256,
          score: 1.5,
        }),
      ).toThrow(/score must be a finite number/)
    })

    it('accepts boundary values 0 and 1', () => {
      expect(() =>
        deviceFingerprintDetector({ store: new AuthMemoryDeviceFingerprintStore(), authSha256: sha256, score: 0 }),
      ).not.toThrow()
      expect(() =>
        deviceFingerprintDetector({ store: new AuthMemoryDeviceFingerprintStore(), authSha256: sha256, score: 1 }),
      ).not.toThrow()
    })
  })
})
