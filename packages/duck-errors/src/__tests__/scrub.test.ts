import { describe, expect, it } from 'vitest'
import { isSecretKey, scrubMeta } from '../scrub'

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
    expect(isSecretKey('tokenCount')).toBe(true)
    expect(isSecretKey('email')).toBe(false)
  })
})

describe('scrubMeta', () => {
  it('drops a secret-shaped top-level key', () => {
    const out = scrubMeta({ token: 'leak-me', roleId: 'r1' })
    expect(out).not.toHaveProperty('token')
    expect(out['roleId']).toBe('r1')
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
    let shallow: Record<string, unknown> = { password: 'leak-me', ok: 1 }
    for (let i = 0; i < 6; i++) shallow = { nested: shallow }
    const out = scrubMeta(shallow)
    expect(JSON.stringify(out)).not.toContain('[depth-cap]')
    expect(JSON.stringify(out)).not.toContain('leak-me')
    expect(JSON.stringify(out)).not.toContain('password')
    expect(JSON.stringify(out)).toContain('"ok":1')
  })

  it('keeps a Date whole rather than walking it into an empty object', () => {
    const at = new Date('2026-01-02T03:04:05.000Z')
    expect(scrubMeta({ at })).toEqual({ at })
  })

  it('survives a circular reference', () => {
    const cycle: Record<string, unknown> = { name: 'loop' }
    cycle['self'] = cycle
    expect(() => scrubMeta(cycle)).not.toThrow()
  })

  it('leaves primitives, empty arrays and empty objects alone', () => {
    const out = scrubMeta({ n: 1, s: 'str', t: true, arr: [], obj: {} })
    expect(out).toMatchObject({ n: 1, s: 'str', t: true, arr: [], obj: {} })
  })
})
