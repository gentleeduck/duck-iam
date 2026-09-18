import { describe, expect, it } from 'vitest'
import { isSecretKey, redactSecrets } from '../errors.scrub'

/** Build `{ a: { a: { ... { password: 'hunter2' } } } }`, `depth` objects deep. */
function nest(depth: number, leaf: object): object {
  let out = leaf
  for (let i = 0; i < depth; i++) out = { a: out }
  return out
}

/** Walk to the deepest object and hand it back, so a test can read the leaf whatever the depth. */
function leafOf(value: unknown): unknown {
  let cur = value
  while (typeof cur === 'object' && cur !== null && 'a' in cur) cur = (cur as { a: unknown }).a
  return cur
}

describe('isSecretKey', () => {
  it('matches the names a caller invents for a secret', () => {
    for (const key of ['password', 'oldPassword', 'userSecret', 'apiToken', 'api_key', 'refresh_token', 'pwHash']) {
      expect(isSecretKey(key)).toBe(true)
    }
  })

  it('is deliberately a substring match, so it over-redacts rather than under-redacts', () => {
    expect(isSecretKey('tokenCount')).toBe(true)
    expect(isSecretKey('email')).toBe(false)
  })
})

describe('redactSecrets', () => {
  it('replaces a secret value at the top level, keeping the shape', () => {
    expect(redactSecrets({ email: 'a@b.c', password: 'hunter2' })).toEqual({
      email: 'a@b.c',
      password: '[redacted]',
    })
  })

  it('reaches a secret nested inside arrays and objects', () => {
    expect(redactSecrets({ users: [{ email: 'a@b.c', token: 'tok' }] })).toEqual({
      users: [{ email: 'a@b.c', token: '[redacted]' }],
    })
  })

  it('keeps a Date whole rather than walking it into an empty object', () => {
    const at = new Date('2026-01-02T03:04:05.000Z')
    expect(redactSecrets({ at })).toEqual({ at })
  })

  it('does not hand back a raw subtree once it runs out of depth', () => {
    // This is the whole point of the cap. Returning the value unwalked - as it did - means a payload
    // nested past the cap carries its secrets out verbatim, and the redaction reads as if it ran.
    const deep = nest(20, { password: 'hunter2' })

    expect(JSON.stringify(redactSecrets(deep))).not.toContain('hunter2')
  })

  it('marks the truncation rather than dropping it silently', () => {
    expect(leafOf(redactSecrets(nest(20, { password: 'hunter2' })))).toBe('[depth-cap]')
  })

  it('still redacts normally right up to the cap', () => {
    expect(leafOf(redactSecrets(nest(6, { password: 'hunter2' })))).toEqual({ password: '[redacted]' })
  })
})
