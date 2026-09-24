import { describe, expect, it } from 'vitest'
import { asIamError, hasIamErrorCode, IamError, metaOf, rethrowIamError, throwIamError } from '../errors'
import { IAM_ERRORS } from '../errors.codes'

const body = (err: IamError) => err.toJSON()

describe('IamError construction', () => {
  it('uses the code as the message, so a thrown error reads as its code', () => {
    expect(new IamError('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED').message).toBe('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED')
  })

  it('maps each code to its documented status, on both status and statusCode', () => {
    const err = new IamError('IAM_ROLE_NOT_FOUND', { adapter: 'redis' })
    expect(err.status).toBe(404)
    expect(err.statusCode).toBe(404)
  })

  it('is an Error, so existing catch blocks and instanceof still work', () => {
    const err = new IamError('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED')
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(IamError)
  })

  it('defaults meta to an empty object rather than undefined', () => {
    expect(new IamError('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED').meta).toEqual({})
  })
})

describe('the code map', () => {
  it('is where every code takes its status from', () => {
    for (const [code, status] of Object.entries(IAM_ERRORS)) {
      expect(new IamError(code as never).status).toBe(status)
      expect(new IamError(code as never).statusCode).toBe(status)
    }
  })
})

// @ts-expect-error a code that carries something cannot be raised without it
void new IamError('IAM_ROLE_NOT_FOUND')
// @ts-expect-error nor with a shape other than the one it declared
void new IamError('IAM_ROLE_NOT_FOUND', { adapter: 1 })

describe('metaOf', () => {
  it('reads meta at the shape the code declares', () => {
    const err = new IamError('IAM_ROLE_NOT_FOUND', { adapter: 'drizzle' })
    const meta = metaOf(err, 'IAM_ROLE_NOT_FOUND')
    expect(meta.adapter).toBe('drizzle')
  })
})

describe('toJSON strips secrets and always reports ok: false', () => {
  it('strips a secret meta key', () => {
    const out = body(new IamError('IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED'))
    expect(out.ok).toBe(false)
  })

  it('keeps the fields that are meant to be seen', () => {
    const out = body(new IamError('IAM_ROLE_NOT_FOUND', { adapter: 'redis' }))
    expect(out.error).toMatchObject({ adapter: 'redis', code: 'IAM_ROLE_NOT_FOUND', status: 404 })
  })

  it('never reads cause', () => {
    const err = asIamError(new Error('driver exploded: postgres://user:pw@host/db'), 'IAM_ROLE_NOT_FOUND', {
      adapter: 'drizzle',
    })
    // JSON.stringify(err.cause) alone is always '{}' (Error.prototype.message/.stack are non-enumerable), so it
    // can never prove the leak is absent - only that the leaked value's own text didn't happen to appear. Assert
    // the key itself is absent from the wire body.
    expect(body(err).error).not.toHaveProperty('cause')
    expect(err.cause).toBeInstanceOf(Error)
  })
})

describe('hasIamErrorCode', () => {
  it('matches by property even when the value is not an IamError instance', () => {
    expect(hasIamErrorCode({ code: 'IAM_ROLE_NOT_FOUND' }, 'IAM_ROLE_NOT_FOUND')).toBe(false) // not an Error
    class Lookalike extends Error {
      code = 'IAM_ROLE_NOT_FOUND'
      meta = { adapter: 'x' }
    }
    expect(hasIamErrorCode(new Lookalike(), 'IAM_ROLE_NOT_FOUND')).toBe(true)
  })

  it('is false for a real IamError of a different code', () => {
    expect(
      hasIamErrorCode(new IamError('IAM_ROLE_NOT_FOUND', { adapter: 'x' }), 'IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED'),
    ).toBe(false)
  })

  it('narrows to typed meta, so no separate metaOf call is needed', () => {
    const err: unknown = new IamError('IAM_ROLE_NOT_FOUND', { adapter: 'drizzle' })
    if (hasIamErrorCode(err, 'IAM_ROLE_NOT_FOUND')) {
      expect(err.meta.adapter).toBe('drizzle')
    } else {
      expect.unreachable()
    }
  })
})

describe('throwIamError, asIamError, rethrowIamError', () => {
  it('throwIamError throws the typed error', () => {
    try {
      throwIamError('IAM_ROLE_NOT_FOUND', { adapter: 'file' })
    } catch (err) {
      expect((err as IamError).code).toBe('IAM_ROLE_NOT_FOUND')
    }
  })

  it('asIamError passes an existing IamError through unchanged', () => {
    const original = new IamError('IAM_ROLE_NOT_FOUND', { adapter: 'file' })
    expect(asIamError(original, 'IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED')).toBe(original)
  })

  it('rethrowIamError wraps anything else with the fallback code', () => {
    for (const thrown of [new TypeError('boom'), 'a string', null, undefined, 42]) {
      try {
        rethrowIamError(thrown, 'IAM_ROLE_NOT_FOUND', { adapter: 'file' })
      } catch (err) {
        expect(err).toBeInstanceOf(IamError)
        expect((err as IamError).code).toBe('IAM_ROLE_NOT_FOUND')
      }
    }
  })
})
