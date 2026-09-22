import { describe, expect, it } from 'vitest'
import { type Answer, answer } from '../answer'
import { AuthError } from '../errors'

const ABSENT_CODES = [
  'AUTH_CREDENTIAL_NOT_FOUND',
  'AUTH_IDEMPOTENCY_MISS',
  'AUTH_IDENTITY_NOT_FOUND',
  'AUTH_MEMBERSHIP_NOT_FOUND',
  'AUTH_OPERATION_NOT_FOUND',
  'AUTH_ORG_NOT_FOUND',
  'AUTH_SESSION_REVOKED',
] as const

describe('answer', () => {
  it('resolves the value untouched', async () => {
    expect(await answer(Promise.resolve({ id: 'a' }))).toEqual({ id: 'a' })
  })

  it('orNull answers null for every absent code', async () => {
    for (const code of ABSENT_CODES) {
      const miss = code === 'AUTH_SESSION_REVOKED' ? new AuthError(code, { reason: 'gone' }) : new AuthError(code)
      expect(await answer(Promise.reject(miss)).orNull()).toBeNull()
    }
  })

  it('orNull rethrows anything else, so a store that is down is not a row that is not there', async () => {
    const down = new AuthError('AUTH_ADAPTER_FAILED')
    await expect(answer(Promise.reject(down)).orNull()).rejects.toBe(down)
    // A refused argument is loud even through the escape hatch.
    const refused = new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'email is blank' })
    await expect(answer(Promise.reject(refused)).orNull()).rejects.toBe(refused)
  })

  it('orDefault substitutes for absence alone', async () => {
    const miss = answer<{ id: string }>(Promise.reject(new AuthError('AUTH_IDENTITY_NOT_FOUND')))
    expect(await miss.orDefault({ id: 'fallback' })).toEqual({ id: 'fallback' })
    const down = answer<{ id: string }>(Promise.reject(new AuthError('AUTH_ADAPTER_FAILED')))
    await expect(down.orDefault({ id: 'fallback' })).rejects.toMatchObject({ code: 'AUTH_ADAPTER_FAILED' })
  })

  it('wrap never rejects and labels a raw throwable, keeping the original on cause', async () => {
    const raw = new Error('connection reset')
    const wrapped = await answer(Promise.reject(raw)).wrap()
    expect(wrapped.data).toBeNull()
    expect(wrapped.error?.code).toBe('AUTH_ADAPTER_FAILED')
    expect(wrapped.error?.cause).toBe(raw)
    expect(await answer(Promise.resolve(1)).wrap()).toEqual({ data: 1, error: null })
  })

  it('reads the same in either order', async () => {
    const miss = () => answer<number>(Promise.reject(new AuthError('AUTH_ORG_NOT_FOUND')))
    expect(await miss().orNull().wrap()).toEqual({ data: null, error: null })
    expect(await miss().wrap().orNull()).toEqual({ data: null, error: null })
  })

  it('takes a thunk, so a body that refuses its arguments rejects rather than throwing at the call site', async () => {
    let refused: Answer.Me<number> | undefined
    // The point of the thunk: building the answer does not throw where the call is written...
    expect(() => {
      refused = answer<number>(() => {
        throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'sid is blank' })
      })
    }).not.toThrow()

    // ...the refusal arrives as a rejection, behind the readers.
    await expect(refused).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
  })
})
