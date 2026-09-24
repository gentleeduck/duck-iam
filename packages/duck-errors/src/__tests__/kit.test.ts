import { describe, expect, it } from 'vitest'
import { detail, fault } from '../brand'
import { createErrorKit } from '../kit'

const TEST_ERRORS = {
  TEST_BARE: 500,
  TEST_DETAIL: detail<{ field: string }>(400),
  TEST_FAULT: fault<{ adapter: string }>(500),
} as const satisfies Record<string, number>

const kit = createErrorKit('TestError', TEST_ERRORS)
const TestError = kit.ErrorClass

describe('construction', () => {
  it('uses the code as the message', () => {
    expect(new TestError('TEST_BARE').message).toBe('TEST_BARE')
  })

  it('maps each code to its declared status, on both status and statusCode', () => {
    const err = new TestError('TEST_FAULT', { adapter: 'redis' })
    expect(err.status).toBe(500)
    expect(err.statusCode).toBe(500)
  })

  it('is a real Error', () => {
    const err = new TestError('TEST_BARE')
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(TestError)
  })

  it('defaults meta to an empty object rather than undefined', () => {
    expect(new TestError('TEST_BARE').meta).toEqual({})
  })

  it('names the class as given', () => {
    expect(new TestError('TEST_BARE').name).toBe('TestError')
  })
})

// @ts-expect-error a code that carries something cannot be raised without it
void new TestError('TEST_DETAIL')
// @ts-expect-error nor with a shape other than the one it declared
void new TestError('TEST_DETAIL', { field: 1 })
// @ts-expect-error a bare code declares no shape, so it cannot be given one at the call site
void new TestError('TEST_BARE', { whatever: true })

describe('class identity across two kits', () => {
  it("never satisfies the other kit's instanceof", () => {
    const otherKit = createErrorKit('OtherError', { OTHER_BARE: 500 } as const)
    const OtherError = otherKit.ErrorClass
    const mine = new TestError('TEST_BARE')
    const theirs = new OtherError('OTHER_BARE')
    expect(mine).not.toBeInstanceOf(OtherError)
    expect(theirs).not.toBeInstanceOf(TestError)
  })
})

describe('toJSON', () => {
  it('scrubs secrets and always reports ok: false', () => {
    const err = kit.fail('TEST_DETAIL', { field: 'x' })
    expect(err.toJSON()).toEqual({ ok: false, error: { code: 'TEST_DETAIL', status: 400, field: 'x' } })
  })

  it('never reads cause', () => {
    const err = kit.asError(new Error('driver exploded: postgres://user:pw@host/db'), 'TEST_FAULT', { adapter: 'x' })
    expect(JSON.stringify(err.toJSON())).not.toContain('postgres://')
    expect(err.cause).toBeInstanceOf(Error)
  })
})

describe('fail, throwError, asError, rethrowError, hasErrorCode, metaOf', () => {
  it('fail constructs without throwing', () => {
    const err = kit.fail('TEST_BARE')
    expect(err).toBeInstanceOf(TestError)
  })

  it('throwError throws the typed error', () => {
    try {
      kit.throwError('TEST_FAULT', { adapter: 'file' })
      expect.unreachable()
    } catch (err) {
      expect(err).toBeInstanceOf(TestError)
    }
  })

  it('asError passes an existing instance through unchanged', () => {
    const original = kit.fail('TEST_FAULT', { adapter: 'file' })
    expect(kit.asError(original, 'TEST_BARE')).toBe(original)
  })

  it('rethrowError wraps anything else under the fallback code', () => {
    for (const thrown of [new TypeError('boom'), 'a string', null, undefined, 42]) {
      try {
        kit.rethrowError(thrown, 'TEST_FAULT', { adapter: 'file' })
        expect.unreachable()
      } catch (err) {
        expect(err).toBeInstanceOf(TestError)
      }
    }
  })

  it('hasErrorCode narrows by property, not instanceof', () => {
    class Lookalike extends Error {
      code = 'TEST_FAULT'
      meta = { adapter: 'x' }
    }
    expect(kit.hasErrorCode(new Lookalike(), 'TEST_FAULT')).toBe(true)
    expect(kit.hasErrorCode({ code: 'TEST_FAULT' }, 'TEST_FAULT')).toBe(false)
  })

  it('metaOf reads meta at the shape the code declares', () => {
    const err = kit.fail('TEST_FAULT', { adapter: 'drizzle' })
    expect(kit.metaOf(err, 'TEST_FAULT').adapter).toBe('drizzle')
  })
})
