import { describe, expect, it } from 'vitest'
import { isSecretKey, redactSecrets, scrubMeta } from '../errors.scrub'

describe('isSecretKey', () => {
  it('matches known secret-shaped key names, case-insensitively', () => {
    for (const key of ['secret', 'Password', 'PRIVATE_KEY', 'token', 'apiToken', 'credential', 'Hash']) {
      expect(isSecretKey(key)).toBe(true)
    }
  })

  it('leaves an ordinary key alone', () => {
    for (const key of ['roleId', 'policyId', 'field', 'operator', 'reason', 'issues', 'adapter']) {
      expect(isSecretKey(key)).toBe(false)
    }
  })

  it('is deliberately a substring match, so it over-redacts rather than under-redacts', () => {
    // A word-boundary-anchored rewrite (`\btoken\b`) would miss this: there is no boundary between the
    // lowercase 'i' and the uppercase 'T' of "Token" mid-identifier, so `apiTokenValue`-shaped keys would
    // stop matching and leak.
    expect(isSecretKey('tokenCount')).toBe(true)
    expect(isSecretKey('email')).toBe(false)
  })
})

describe('scrubMeta', () => {
  it('drops a secret-shaped top-level key', () => {
    const out = scrubMeta({ token: 'leak-me', roleId: 'r1' })
    expect(out).not.toHaveProperty('token')
    expect(out.roleId).toBe('r1')
  })

  it('drops a secret nested inside an object', () => {
    const out = scrubMeta({ detail: { inner: { password: 'leak-me' } } })
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('drops a secret inside an array of objects', () => {
    const out = scrubMeta({ items: [{ ok: 1 }, { token: 'leak-me' }] })
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('caps depth rather than recursing forever', () => {
    let deep: Record<string, unknown> = { secret: 'leak-me' }
    for (let i = 0; i < 50; i++) deep = { nested: deep }
    const out = scrubMeta(deep)
    expect(JSON.stringify(out)).toContain('[depth-cap]')
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('still walks and drops a secret right up to the cap, rather than truncating too early', () => {
    // Distinct from the test above: a `DEPTH_CAP` set too low would also make that test pass (the secret
    // would still be gone, just for the wrong reason), by truncating legitimate structure - here, the six
    // levels of `nested` wrapping - before it was ever walked.
    let shallow: Record<string, unknown> = { password: 'leak-me', ok: 1 }
    for (let i = 0; i < 6; i++) shallow = { nested: shallow }
    const out = scrubMeta(shallow)
    expect(JSON.stringify(out)).not.toContain('[depth-cap]')
    expect(JSON.stringify(out)).not.toContain('leak-me')
    expect(JSON.stringify(out)).not.toContain('password')
    expect(JSON.stringify(out)).toContain('"ok":1')
  })

  it('keeps a Date whole rather than walking it into an empty object', () => {
    // `Object.entries` on a Date yields no own enumerable properties, so losing this check turns any
    // `Date`-valued meta field into `{}` silently.
    const at = new Date('2026-01-02T03:04:05.000Z')
    expect(scrubMeta({ at })).toEqual({ at })
  })

  it('survives a circular reference', () => {
    const cycle: Record<string, unknown> = { name: 'loop' }
    cycle.self = cycle
    expect(() => scrubMeta(cycle)).not.toThrow()
  })

  it('leaves primitives, empty arrays and empty objects alone', () => {
    const out = scrubMeta({ n: 1, s: 'str', t: true, arr: [], obj: {} })
    expect(out).toMatchObject({ n: 1, s: 'str', t: true, arr: [], obj: {} })
  })
})

describe('redactSecrets', () => {
  it('replaces a secret value with a marker but keeps the shape', () => {
    const out = redactSecrets({ token: 'leak-me', roleId: 'r1' }) as Record<string, unknown>
    expect(out.token).toBe('[redacted]')
    expect(out.roleId).toBe('r1')
  })

  it('keeps a Date whole rather than walking it into an empty object', () => {
    // `redactSecrets` carries its own `instanceof Date` check, separate from `scrubMeta`'s - a regression
    // in one does not imply a regression in the other.
    const at = new Date('2026-01-02T03:04:05.000Z')
    expect(redactSecrets({ at })).toEqual({ at })
  })
})
