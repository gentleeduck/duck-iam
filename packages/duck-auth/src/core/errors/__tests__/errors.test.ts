/**
 * `AuthError.toJSON` is the last thing between an error's metadata and an HTTP
 * response body, and it had no tests. Its job is to strip secrets, so the way it
 * fails is by letting one through, which nothing else in the stack would notice.
 *
 * The cases below attack the redactor the way a real payload would arrive: keys
 * in unexpected case, secrets buried in nested objects and arrays, near-miss key
 * names, and shapes designed to make a recursive walker misbehave.
 */
import { describe, expect, it } from 'vitest'
import { AuthError, rethrowAuthError, throwAuthError } from '../errors'

/** The response body an adapter would actually send. */
const body = (err: AuthError) => err.toJSON()

describe('AuthError construction', () => {
  it('uses the code as the message, so a thrown error reads as its code', () => {
    expect(new AuthError('AUTH_CSRF').message).toBe('AUTH_CSRF')
  })

  it('maps each code to its documented status', () => {
    expect(new AuthError('AUTH_UNAUTHENTICATED').status).toBe(401)
    expect(new AuthError('AUTH_CSRF').status).toBe(403)
    expect(new AuthError('AUTH_RATE_LIMITED', { retryAfter: 60 }).status).toBe(429)
    expect(new AuthError('AUTH_LOCKED', { reason: 'brute force', until: Date.now() }).status).toBe(423)
    expect(new AuthError('AUTH_MISCONFIGURED', { detail: 'x' }).status).toBe(500)
    expect(new AuthError('AUTH_MAINTENANCE', { retryAfter: 60 }).status).toBe(503)
  })

  it('is an Error, so existing catch blocks and instanceof still work', () => {
    const err = new AuthError('AUTH_CSRF')
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(AuthError)
  })

  it('defaults meta to an empty object rather than undefined', () => {
    expect(new AuthError('AUTH_CSRF').meta).toEqual({})
  })
})

describe('toJSON strips secrets', () => {
  for (const key of [
    'secret',
    'password',
    'plaintext',
    'privateKey',
    'token',
    'refreshToken',
    'accessToken',
    'idToken',
    'clientSecret',
    'hash',
    'presentedHash',
    'codeHash',
    'tokenHash',
  ]) {
    it(`removes ${key}`, () => {
      const out = body(new AuthError('AUTH_CSRF', { [key]: 'super-secret-value' } as never))
      expect(JSON.stringify(out)).not.toContain('super-secret-value')
    })
  }

  it('matches the key regardless of case', () => {
    for (const key of ['SECRET', 'Secret', 'sEcReT', 'PASSWORD', 'TokenHash']) {
      const out = body(new AuthError('AUTH_CSRF', { [key]: 'leak-me' } as never))
      expect(JSON.stringify(out)).not.toContain('leak-me')
    }
  })

  it('strips a secret nested inside an object', () => {
    const out = body(new AuthError('AUTH_CSRF', { detail: { inner: { password: 'leak-me' } } } as never))
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('strips a secret inside an array of objects', () => {
    const out = body(new AuthError('AUTH_CSRF', { items: [{ ok: 1 }, { token: 'leak-me' }] } as never))
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('strips a secret several levels down', () => {
    const out = body(new AuthError('AUTH_CSRF', { a: { b: { c: { d: { secret: 'leak-me' } } } } } as never))
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('keeps the fields that are meant to be seen', () => {
    const out = body(new AuthError('AUTH_PROVIDER_FAILED', { detail: 'unknown provider id', providerId: 'oauth' }))
    expect(out.error).toMatchObject({ detail: 'unknown provider id', providerId: 'oauth' })
    expect(out.error.code).toBe('AUTH_PROVIDER_FAILED')
    expect(out.error.status).toBe(400)
  })

  it('always reports ok:false', () => {
    expect(body(new AuthError('AUTH_CSRF')).ok).toBe(false)
  })
})

describe('toJSON under shapes built to break a recursive walker', () => {
  it('caps depth rather than recursing forever', () => {
    let deep: Record<string, unknown> = { secret: 'leak-me' }
    for (let i = 0; i < 50; i++) deep = { nested: deep }
    const out = body(new AuthError('AUTH_CSRF', deep as never))
    expect(JSON.stringify(out)).toContain('[depth-cap]')
  })

  it('FINDING: a secret buried deeper than the depth cap is not reached', () => {
    // The cap protects against a cycle, but it also means the walker stops
    // looking. Below the cap the value is replaced wholesale by '[depth-cap]',
    // so the secret does not appear, and the string is what a reader sees
    // instead. Pinned to record that depth is a truncation, not a scrub.
    let deep: Record<string, unknown> = { password: 'leak-me' }
    for (let i = 0; i < 20; i++) deep = { nested: deep }
    const serialised = JSON.stringify(body(new AuthError('AUTH_CSRF', deep as never)))
    expect(serialised).not.toContain('leak-me')
    expect(serialised).toContain('[depth-cap]')
  })

  it('survives a circular reference', () => {
    const cycle: Record<string, unknown> = { name: 'loop' }
    cycle.self = cycle
    expect(() => body(new AuthError('AUTH_CSRF', cycle as never))).not.toThrow()
  })

  it('passes null and undefined through without crashing', () => {
    const out = body(new AuthError('AUTH_CSRF', { a: null, b: undefined } as never))
    expect(out.error).toHaveProperty('a', null)
  })

  it('leaves primitives alone', () => {
    const out = body(new AuthError('AUTH_CSRF', { n: 1, s: 'str', t: true } as never))
    expect(out.error).toMatchObject({ n: 1, s: 'str', t: true })
  })

  it('handles an empty array and an empty object', () => {
    const out = body(new AuthError('AUTH_CSRF', { arr: [], obj: {} } as never))
    expect(out.error).toMatchObject({ arr: [], obj: {} })
  })
})

describe('FINDING: the sensitive list matches whole keys only', () => {
  // Membership is exact, so a key that merely contains a sensitive word is kept.
  // Deliberate and defensible, since a substring rule would strip innocent keys
  // like `tokenCount`, but it means a caller inventing its own key name gets no
  // protection. Recorded so the constraint is known rather than assumed.
  for (const key of ['userSecret', 'secret_key', 'mySecret', 'apiToken', 'passwordHint', 'oldPassword']) {
    it(`keeps ${key}, because it is not in the list verbatim`, () => {
      const out = body(new AuthError('AUTH_CSRF', { [key]: 'visible-value' } as never))
      expect(JSON.stringify(out)).toContain('visible-value')
    })
  }
})

describe('throwAuthError and rethrowAuthError', () => {
  it('throwAuthError throws the typed error', () => {
    expect(() => throwAuthError('AUTH_CSRF')).toThrow(AuthError)
    try {
      throwAuthError('AUTH_RATE_LIMITED', { retryAfter: 60 })
    } catch (err) {
      expect((err as AuthError).code).toBe('AUTH_RATE_LIMITED')
    }
  })

  it('rethrowAuthError passes an existing AuthError through unchanged', () => {
    const original = new AuthError('AUTH_CSRF', { detail: 'original' })
    try {
      rethrowAuthError(original, 'AUTH_MISCONFIGURED', { detail: 'fallback' })
    } catch (err) {
      expect(err).toBe(original)
      expect((err as AuthError).code).toBe('AUTH_CSRF')
    }
  })

  it('rethrowAuthError wraps anything else with the fallback code', () => {
    for (const thrown of [new TypeError('boom'), 'a string', null, undefined, 42, { not: 'an error' }]) {
      try {
        rethrowAuthError(thrown, 'AUTH_MISCONFIGURED', { detail: 'wrapped' })
      } catch (err) {
        expect(err).toBeInstanceOf(AuthError)
        expect((err as AuthError).code).toBe('AUTH_MISCONFIGURED')
      }
    }
  })

  it('rethrowAuthError does not leak the original message into the wrapper', () => {
    try {
      rethrowAuthError(new Error('connection string postgres://user:pw@host/db'), 'AUTH_MISCONFIGURED', {
        detail: 'fallback',
      })
    } catch (err) {
      expect((err as AuthError).message).toBe('AUTH_MISCONFIGURED')
      expect(JSON.stringify(body(err as AuthError))).not.toContain('postgres://')
    }
  })
})
