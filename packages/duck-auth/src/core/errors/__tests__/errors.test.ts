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

/** An `AuthError` carrying meta its code does not declare, as an untyped call site can build one. */
function withMeta(code: string, meta: Record<string, unknown>): AuthError {
  return Reflect.construct(AuthError, [code, meta])
}

describe('AuthError construction', () => {
  it('uses the code as the message, so a thrown error reads as its code', () => {
    expect(new AuthError('AUTH_CSRF').message).toBe('AUTH_CSRF')
  })

  it('maps each code to its documented status', () => {
    expect(new AuthError('AUTH_UNAUTHENTICATED').status).toBe(401)
    expect(new AuthError('AUTH_CSRF').status).toBe(403)
    expect(new AuthError('AUTH_RATE_LIMITED', { retryAfter: 60 }).status).toBe(429)
    expect(new AuthError('AUTH_MISCONFIGURED', { detail: 'x' }).status).toBe(500)
    expect(new AuthError('AUTH_ADAPTER_UNAVAILABLE').status).toBe(503)
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
      expect(withMeta(code, {}).status).toBe(status)
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
    it(`removes ${key} and keeps the field beside it`, () => {
      expect(body(withMeta('AUTH_RATE_LIMITED', { [key]: 'super-secret-value', retryAfter: 30 }))).toEqual({
        ok: false,
        error: { code: 'AUTH_RATE_LIMITED', status: 429, retryAfter: 30 },
      })
    })
  }

  it('strips only the wire copy, leaving the meta a server-side handler reads', () => {
    const err = withMeta('AUTH_INVALID_CREDENTIALS', { secret: 'super-secret-hash' })
    body(err)
    expect(err.meta).toEqual({ secret: 'super-secret-hash' })
  })

  it('matches the key regardless of case', () => {
    for (const key of ['SECRET', 'Secret', 'sEcReT', 'PASSWORD', 'TokenHash']) {
      const out = body(withMeta('AUTH_RATE_LIMITED', { [key]: 'leak-me' }))
      expect(JSON.stringify(out)).not.toContain('leak-me')
    }
  })

  it('strips a secret nested inside an object, keeping its siblings', () => {
    const out = body(withMeta('AUTH_PROVIDER_FAILED', { providerId: 'oauth:test', user: { id: 'u1', password: 'x' } }))
    expect(out.error).toEqual({
      code: 'AUTH_PROVIDER_FAILED',
      status: 400,
      providerId: 'oauth:test',
      user: { id: 'u1' },
    })
  })

  it('strips a secret inside an array of objects', () => {
    const out = body(withMeta('AUTH_RATE_LIMITED', { items: [{ ts: 1 }, { ts: 2, token: 'leak-me' }] }))
    expect(out.error.items).toEqual([{ ts: 1 }, { ts: 2 }])
  })

  it('strips a secret several levels down', () => {
    const out = body(withMeta('AUTH_RATE_LIMITED', { a: { b: { c: { d: { secret: 'leak-me' } } } } }))
    expect(JSON.stringify(out)).not.toContain('leak-me')
  })

  it('keeps the fields that are meant to be seen', () => {
    const out = body(new AuthError('AUTH_PROVIDER_FAILED', { detail: 'unknown provider id', providerId: 'oauth' }))
    expect(out.error).toMatchObject({ detail: 'unknown provider id', providerId: 'oauth' })
    expect(out.error.code).toBe('AUTH_PROVIDER_FAILED')
    expect(out.error.status).toBe(400)
  })
})

describe('toJSON under shapes built to break a recursive walker', () => {
  it('caps depth rather than recursing forever', () => {
    let deep: Record<string, unknown> = { secret: 'leak-me' }
    for (let i = 0; i < 50; i++) deep = { nested: deep }
    const out = body(withMeta('AUTH_RATE_LIMITED', deep))
    expect(JSON.stringify(out)).toContain('[depth-cap]')
  })

  it('truncates past the depth cap rather than walking on', () => {
    // The cap is what survives a cycle. Past it the value is replaced wholesale by '[depth-cap]',
    // so a secret below the cap does not appear either; the marker is what a reader sees instead.
    let deep: Record<string, unknown> = { password: 'leak-me' }
    for (let i = 0; i < 20; i++) deep = { nested: deep }
    const serialised = JSON.stringify(body(withMeta('AUTH_RATE_LIMITED', deep)))
    expect(serialised).not.toContain('leak-me')
    expect(serialised).toContain('[depth-cap]')
  })

  it('survives a circular reference', () => {
    const cycle: Record<string, unknown> = { name: 'loop' }
    cycle.self = cycle
    expect(() => body(withMeta('AUTH_RATE_LIMITED', cycle))).not.toThrow()
  })

  it('passes null and undefined through without crashing', () => {
    const out = body(withMeta('AUTH_RATE_LIMITED', { a: null, b: undefined }))
    expect(out.error).toHaveProperty('a', null)
  })

  it('leaves primitives alone', () => {
    const out = body(withMeta('AUTH_RATE_LIMITED', { n: 1, s: 'str', t: true }))
    expect(out.error).toMatchObject({ n: 1, s: 'str', t: true })
  })

  it('handles an empty array and an empty object', () => {
    const out = body(withMeta('AUTH_RATE_LIMITED', { arr: [], obj: {} }))
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
      const out = body(withMeta('AUTH_RATE_LIMITED', { [key]: 'visible-value' }))
      expect(JSON.stringify(out)).not.toContain('visible-value')
    })
  }
})

describe('throwAuthError and rethrowAuthError', () => {
  it('throwAuthError throws the typed error', () => {
    expect(() => throwAuthError('AUTH_CSRF')).toThrow(AuthError)
    expect(() => throwAuthError('AUTH_RATE_LIMITED', { retryAfter: 60 })).toThrowError(
      expect.objectContaining({ code: 'AUTH_RATE_LIMITED', meta: { retryAfter: 60 } }),
    )
  })

  it('rethrowAuthError passes an existing AuthError through unchanged', () => {
    const original = new AuthError('AUTH_RATE_LIMITED', { retryAfter: 60 })
    let caught: unknown
    try {
      rethrowAuthError(original, 'AUTH_MISCONFIGURED', { detail: 'fallback' })
    } catch (err) {
      caught = err
    }
    expect(caught).toBe(original)
  })

  it('rethrowAuthError wraps anything else with the fallback code', () => {
    for (const thrown of [new TypeError('boom'), 'a string', null, undefined, 42, { not: 'an error' }]) {
      const rethrow = () => rethrowAuthError(thrown, 'AUTH_MISCONFIGURED', { detail: 'wrapped' })
      expect(rethrow).toThrow(AuthError)
      expect(rethrow).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: 'wrapped' } }))
    }
  })

  it('rethrowAuthError does not leak the original message into the wrapper', () => {
    let caught: unknown
    try {
      rethrowAuthError(new Error('connection string postgres://user:pw@host/db'), 'AUTH_MISCONFIGURED', {
        detail: 'fallback',
      })
    } catch (err) {
      caught = err
    }
    if (!(caught instanceof AuthError)) return expect.unreachable('rethrowAuthError should throw an AuthError')
    expect(caught.message).toBe('AUTH_MISCONFIGURED')
    expect(JSON.stringify(body(caught))).not.toContain('postgres://')
  })
})
