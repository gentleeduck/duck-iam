/**
 * `AuthMemoryDeviceFingerprintStore`'s constructor doc promises the per-identity set is "bounded both ways",
 * because "one request per rotated user agent would otherwise grow that set without bound". Both bounds are
 * applied as a bare comparison against the configured number — `seen.size > this._maxPerIdentity` and
 * `now - at > this._ttlMs` — and every comparison against `NaN` is false, so a non-finite value does not
 * loosen the bound, it removes it. The two other constructors in this module, `deviceFingerprintDetector`
 * and `authImpossibleTravelDetector`, both validate their numeric config and throw `AUTH_MISCONFIGURED`;
 * this one took the same shape of config and validated nothing, which is how `Number(process.env.FP_MAX)`
 * on an unset variable reached the comparison.
 *
 * Zero and negative fail the other way: nothing is ever remembered, so every request is a first sighting
 * and a detector scored at the default 0.7 steps up every authenticated request it sees.
 */
import { describe, expect, it, vi } from 'vitest'
import { AuthMemoryDeviceFingerprintStore } from '~/core/anomaly'
import { AuthError } from '~/core/errors'

/** Fill past the cap and answer whether the oldest survived it. Asked of the oldest and newest only,
 *  because `checkAndRemember` inserts on a miss and so cannot be used to count a set without changing it. */
async function oldestSurvived(store: AuthMemoryDeviceFingerprintStore, count: number): Promise<boolean> {
  for (let i = 0; i < count; i++) await store.checkAndRemember('u1', `fp${i}`)
  expect(await store.checkAndRemember('u1', `fp${count - 1}`)).toBe(true)
  return store.checkAndRemember('u1', 'fp0')
}

describe('the memory fingerprint store refuses a bound it cannot apply', () => {
  it('evicts past maxPerIdentity, which is the promise under test', async () => {
    expect(await oldestSurvived(new AuthMemoryDeviceFingerprintStore({ maxPerIdentity: 3 }), 10)).toBe(false)
  })

  it('refuses a non-finite cap rather than growing without bound', () => {
    expect(() => new AuthMemoryDeviceFingerprintStore({ maxPerIdentity: Number.NaN })).toThrow(AuthError)
  })

  it('refuses a non-finite ttl rather than remembering a device forever', () => {
    expect(() => new AuthMemoryDeviceFingerprintStore({ ttlMs: Number.NaN })).toThrow(AuthError)
  })

  it('refuses a cap that remembers nothing, which flags every request as a new device', () => {
    expect(() => new AuthMemoryDeviceFingerprintStore({ maxPerIdentity: 0 })).toThrow(AuthError)
    expect(() => new AuthMemoryDeviceFingerprintStore({ maxPerIdentity: -1 })).toThrow(AuthError)
  })

  it('refuses a ttl that expires every sighting', () => {
    expect(() => new AuthMemoryDeviceFingerprintStore({ ttlMs: 0 })).toThrow(AuthError)
    expect(() => new AuthMemoryDeviceFingerprintStore({ ttlMs: -1 })).toThrow(AuthError)
  })

  it('names the value it was given, as the two sibling constructors do', () => {
    // Read off `meta.detail`: an `AuthError`'s `message` is its bare code, so a regex on the thrown error
    // would match `AUTH_MISCONFIGURED` and nothing about the setting.
    const detail = (cfg: { maxPerIdentity?: number; ttlMs?: number }): string => {
      try {
        new AuthMemoryDeviceFingerprintStore(cfg)
      } catch (err) {
        return String((err as { meta: { detail: string } }).meta.detail)
      }
      return ''
    }
    expect(detail({ maxPerIdentity: Number.NaN })).toContain(
      'maxPerIdentity must be a finite positive number (got NaN)',
    )
    expect(detail({ ttlMs: Number.POSITIVE_INFINITY })).toContain(
      'ttlMs must be a finite positive number (got Infinity)',
    )
  })

  it('still expires a sighting past a ttl it does accept', async () => {
    const store = new AuthMemoryDeviceFingerprintStore({ ttlMs: 60_000 })
    await store.checkAndRemember('u1', 'a')
    expect(await store.checkAndRemember('u1', 'a')).toBe(true)
    vi.useFakeTimers()
    try {
      vi.setSystemTime(Date.now() + 120_000)
      expect(await store.checkAndRemember('u1', 'a')).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('leaves both defaults in place when nothing is passed', async () => {
    expect(() => new AuthMemoryDeviceFingerprintStore()).not.toThrow()
    // 60 past a default cap of 50, so the first is gone and the last is not.
    expect(await oldestSurvived(new AuthMemoryDeviceFingerprintStore(), 60)).toBe(false)
  })
})
