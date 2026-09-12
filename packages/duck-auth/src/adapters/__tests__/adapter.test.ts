import { describe, expect, it } from 'vitest'
import { AuthError, asAuthError, declares, type ErrorMap, errorMap, GENERIC, type RangeOf } from '~/core/errors'
import { AdapterStore } from '../adapter'

/** What this double's calls throw, declared as a real adapter declares its own range. */
const DOUBLE = declares(GENERIC, [
  'AUTH_ALREADY_EXISTS',
  'AUTH_IDENTITY_NOT_FOUND',
  'AUTH_NOT_ENOUGH_PARAMETERS',
  'AUTH_STALE_WRITE',
])
type Double = RangeOf<typeof DOUBLE>

/** A mapper of this double's own, over the same declared range. */
const mapper = (map: (err: unknown) => AuthError): ErrorMap<Double> => errorMap(map, [...DOUBLE.codes])

/** An adapter: the driver call goes through `run`, and the adapter names what its driver threw. */
class Store extends AdapterStore<Double> {
  constructor(toError: ErrorMap<Double> = DOUBLE) {
    super(toError)
  }

  call<T>(thunk: () => Promise<T>) {
    return this.run(thunk)
  }
}

describe('AdapterStore.run', () => {
  it('answers the value, and lets a typed throw through as the same instance', async () => {
    const store = new Store()
    const thrown = new AuthError('AUTH_IDENTITY_NOT_FOUND')

    expect(await store.call(async () => ({ id: 'a' }))).toEqual({ id: 'a' })
    await expect(store.call(() => Promise.reject(thrown))).rejects.toBe(thrown)
  })

  it('catches a synchronous throw from the thunk, not only a rejection', async () => {
    const store = new Store()

    await expect(
      store.call((): Promise<number> => {
        throw new AuthError('AUTH_NOT_ENOUGH_PARAMETERS')
      }),
    ).rejects.toMatchObject({ code: 'AUTH_NOT_ENOUGH_PARAMETERS' })
  })

  it('reports an untyped failure as AUTH_ADAPTER_FAILED, with the original on cause', async () => {
    const broken = new Error('something the driver never documented')

    await expect(new Store().call(() => Promise.reject(broken))).rejects.toMatchObject({
      cause: broken,
      code: 'AUTH_ADAPTER_FAILED',
    })
  })

  it('lets the dialect name what its driver threw', async () => {
    const clash = Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505' })
    const store = new Store(mapper((err) => asAuthError(err, 'AUTH_ALREADY_EXISTS')))

    await expect(store.call(() => Promise.reject(clash))).rejects.toMatchObject({
      cause: clash,
      code: 'AUTH_ALREADY_EXISTS',
    })
  })
})

describe('AdapterStore.answer', () => {
  it('hands the answer itself back, so `wrap` survives - an `async run` would assimilate it and drop it', () => {
    expect(typeof new Store().call(async () => 1).wrap).toBe('function')
  })

  it('attaches to a promise of its own, leaving the caller their own untouched', async () => {
    const theirs = Promise.resolve(1)
    const answer = AdapterStore.answer(theirs)

    expect(answer).not.toBe(theirs)
    expect('wrap' in theirs).toBe(false)
    expect(await answer.wrap()).toEqual({ data: 1, error: null })
  })

  it('names an untyped rejection once, for a promise no dialect mapper ever saw', async () => {
    const raw = new Error('a double standing in for a store')

    expect(await AdapterStore.answer(Promise.reject(raw)).wrap()).toMatchObject({
      data: null,
      error: { cause: raw, code: 'AUTH_ADAPTER_FAILED' },
    })
  })
})

describe('AdapterStore.run().wrap', () => {
  it('answers the value with a null error, and a typed failure as that same instance', async () => {
    const store = new Store()
    const thrown = new AuthError('AUTH_IDENTITY_NOT_FOUND')

    expect(await store.call(async () => ({ id: 'a' })).wrap()).toEqual({ data: { id: 'a' }, error: null })
    expect(await store.call(() => Promise.reject(thrown)).wrap()).toEqual({ data: null, error: thrown })
  })

  it('leaves the same call throwing when nothing asked to wrap it', async () => {
    const store = new Store()

    const stale = new AuthError('AUTH_STALE_WRITE', { actual: 1, expected: 2 })
    await expect(store.call(() => Promise.reject(stale))).rejects.toBe(stale)
  })

  it('carries a non-Error as the cause of a real one rather than handing it back raw', async () => {
    // A dialect mapper that throws instead of answering is the one way a raw value reaches the wrap.
    const store = new Store(
      mapper(() => {
        throw 'the mapper itself broke'
      }),
    )

    const { data, error } = await store.call(() => Promise.reject(new Error('driver'))).wrap()
    expect(data).toBeNull()
    expect(error).toBeInstanceOf(AuthError)
    expect(error?.cause).toBe('the mapper itself broke')
  })

  it('does not leak the driver message into the wire envelope', async () => {
    const store = new Store()
    const { error } = await store
      .call(() => Promise.reject(new Error('relation "auth_identities" does not exist')))
      .wrap()

    expect(JSON.stringify(error)).not.toContain('auth_identities')
  })
})
