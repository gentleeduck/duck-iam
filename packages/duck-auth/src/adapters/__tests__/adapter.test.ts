import { describe, expect, it } from 'vitest'
import { AuthError, asAuthError, declares, type ErrorMap, errorMap, GENERIC, type RangeOf } from '~/core/errors'
import { AdapterStore } from '../adapter'
import type { Adapter } from '../index'
import * as entry from '../index'

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
  it('re-labels a code the map never declared rather than passing it off as one it did', async () => {
    const masked = await new Store().call(() => Promise.reject(new AuthError('AUTH_UNAUTHENTICATED'))).catch((e) => e)

    expect(masked.code).toBe('AUTH_ADAPTER_FAILED')
    // Nothing of the undeclared error survives, not even down the cause chain.
    expect(masked.cause).toBeUndefined()
  })

  it('lets a mapper that throws escape raw, since naming a bare value belongs to the facet', async () => {
    // A dialect mapper that throws instead of answering is the one way a raw value leaves a store. `answer`
    // is what gives it a code and puts it on `cause`, at the boundary a caller actually holds.
    const store = new Store(
      mapper(() => {
        throw 'the mapper itself broke'
      }),
    )

    await expect(store.call(() => Promise.reject(new Error('driver')))).rejects.toBe('the mapper itself broke')
  })

  it('does not leak the driver message into the wire envelope', async () => {
    const store = new Store()
    const error = await store
      .call(() => Promise.reject(new Error('relation "auth_identities" does not exist')))
      .catch((e) => e)

    expect(JSON.stringify(error)).not.toContain('auth_identities')
  })
})

/**
 * `Adapter.Me` is the whole contract a store written outside this package is built against, so dropping it
 * from the entry closes that door while every adapter in this tree keeps working.
 */
type _Me = Adapter.Me

describe('the adapters entry', () => {
  it('exposes the contract a store written outside this package is built against', () => {
    // The type above is the real assertion; it stops compiling if the entry drops it.
    expect(Object.keys(entry)).toEqual(['AdapterStore'])
    expect(new (class extends AdapterStore {})(GENERIC)).toBeInstanceOf(entry.AdapterStore)
  })
})
