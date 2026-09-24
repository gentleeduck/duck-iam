/**
 * `AuthError.toJSON` is the last thing between an error's metadata and an HTTP
 * response body, and it had no tests. Its job is to strip secrets, so the way it
 * fails is by letting one through, which nothing else in the stack would notice.
 */
import { describe, expect, it } from 'vitest'
import { AuthError, rethrowAuthError, throwAuthError } from '../errors'
import { AUTH_ERRORS } from '../errors.codes'

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

  it('names itself AuthError, not the historical AuthError.IAuthError', () => {
    expect(new AuthError('AUTH_CSRF').name).toBe('AuthError')
  })

  it('defaults meta to an empty object rather than undefined', () => {
    expect(new AuthError('AUTH_CSRF').meta).toEqual({})
  })
})

describe('the code map', () => {
  it('keeps a declared status a plain number, which is what every reader of the map takes it for', () => {
    expect(AUTH_ERRORS.AUTH_SESSION_EXPIRED).toBe(401)
    expect(Object.values(AUTH_ERRORS).every((status) => typeof status === 'number')).toBe(true)
  })

  it('is where every code takes its status from, so there is no second table to fall out of step with', () => {
    for (const [code, status] of Object.entries(AUTH_ERRORS)) {
      // `as never`, not `as AuthError.Code`: a widened key declares no meta, which is what lets one line raise all of them.
      expect(new AuthError(code as never).status).toBe(status)
    }
  })
})

// What the map states in types rather than at runtime: each line is the compile error a wrong change gets.
// @ts-expect-error a code that carries something cannot be raised without it
void new AuthError('AUTH_SESSION_EXPIRED')
// @ts-expect-error nor with a shape other than the one it declared
void new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: 'soon' })
// @ts-expect-error a third argument no longer exists — Origin was dropped entirely
void new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: Date.now() }, { providerId: 'x' })

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
      const out = body(new AuthError('AUTH_RATE_LIMITED', { [key]: 'super-secret-value' } as never))
      expect(JSON.stringify(out)).not.toContain('super-secret-value')
    })
  }

  it('matches the key regardless of case', () => {
    for (const key of ['SECRET', 'Secret', 'sEcReT', 'PASSWORD', 'TokenHash']) {
      const out = body(new AuthError('AUTH_RATE_LIMITED', { [key]: 'leak-me' } as never))
      expect(JSON.stringify(out)).not.toContain('leak-me')
    }
  })

  it('strips a secret nested inside an object', () => {
    const out = body(new AuthError('AUTH_RATE_LIMITED', { detail: { inner: { password: 'leak-me' } } } as never))
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('strips a secret inside an array of objects', () => {
    const out = body(new AuthError('AUTH_RATE_LIMITED', { items: [{ ok: 1 }, { token: 'leak-me' }] } as never))
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('strips a secret several levels down', () => {
    const out = body(new AuthError('AUTH_RATE_LIMITED', { a: { b: { c: { d: { secret: 'leak-me' } } } } } as never))
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
    const out = body(new AuthError('AUTH_RATE_LIMITED', deep as never))
    expect(JSON.stringify(out)).toContain('[depth-cap]')
  })

  it('truncates past the depth cap rather than walking on', () => {
    // The cap is what survives a cycle. Past it the value is replaced wholesale by '[depth-cap]',
    // so a secret below the cap does not appear either; the marker is what a reader sees instead.
    let deep: Record<string, unknown> = { password: 'leak-me' }
    for (let i = 0; i < 20; i++) deep = { nested: deep }
    const serialised = JSON.stringify(body(new AuthError('AUTH_RATE_LIMITED', deep as never)))
    expect(serialised).not.toContain('leak-me')
    expect(serialised).toContain('[depth-cap]')
  })

  it('survives a circular reference', () => {
    const cycle: Record<string, unknown> = { name: 'loop' }
    cycle.self = cycle
    expect(() => body(new AuthError('AUTH_RATE_LIMITED', cycle as never))).not.toThrow()
  })

  it('passes null and undefined through without crashing', () => {
    const out = body(new AuthError('AUTH_RATE_LIMITED', { a: null, b: undefined } as never))
    expect(out.error).toHaveProperty('a', null)
  })

  it('leaves primitives alone', () => {
    const out = body(new AuthError('AUTH_RATE_LIMITED', { n: 1, s: 'str', t: true } as never))
    expect(out.error).toMatchObject({ n: 1, s: 'str', t: true })
  })

  it('handles an empty array and an empty object', () => {
    const out = body(new AuthError('AUTH_RATE_LIMITED', { arr: [], obj: {} } as never))
    expect(out.error).toMatchObject({ arr: [], obj: {} })
  })
})

describe('the sensitive list matches a key that merely contains the word', () => {
  // Exact membership kept `oldPassword` and `userSecret`, which are the names a caller invents.
  // A substring rule also strips an innocent `tokenCount`, and losing a number is the cheaper way
  // to be wrong.
  for (const key of [
    'userSecret',
    'secret_key',
    'mySecret',
    'apiToken',
    'passwordHint',
    'oldPassword',
    'otpCode',
    'recoveryToken',
  ]) {
    it(`drops ${key}`, () => {
      const out = body(new AuthError('AUTH_RATE_LIMITED', { [key]: 'visible-value' } as never))
      expect(JSON.stringify(out)).not.toContain('visible-value')
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
    const original = new AuthError('AUTH_RATE_LIMITED', { retryAfter: 60 })
    try {
      rethrowAuthError(original, 'AUTH_MISCONFIGURED', { detail: 'fallback' })
    } catch (err) {
      expect(err).toBe(original)
      expect((err as AuthError).code).toBe('AUTH_RATE_LIMITED')
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
