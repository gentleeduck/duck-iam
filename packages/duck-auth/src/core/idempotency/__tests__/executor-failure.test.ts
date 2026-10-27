import { describe, expect, it, vi } from 'vitest'
import { FakeRedis } from '~/core/drivers/redis-like'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { IdempotencyImpl } from '../idempotency'
import { MemoryIdempotency } from '../idempotency.memory'
import { RedisIdempotency } from '../idempotency.redis'
import type { Idempotency } from '../idempotency.types'

/**
 * An Idempotency-Key exists so a client that saw an error can send the request again under the same key.
 * The claim `handle` takes is a lock over the executor, and it is written with the *response* TTL, a day
 * by default. So every way the executor could fail decided what happened to the key for that whole day.
 *
 * `pollTimeoutMs` is short here so the 409 path finishes quickly; nothing under test reads it otherwise.
 */
const ctx: TenantContext = {}
const ok = (status: number): Idempotency.CachedResponse => ({ body: { status }, createdAt: new Date(), status })

function stores(): Array<[string, Idempotency.Store]> {
  return [
    ['memory', new MemoryIdempotency()],
    ['redis', new RedisIdempotency({ prefix: 'test:idem', redis: new FakeRedis() })],
  ]
}

describe.each(stores())('IdempotencyImpl over the %s store, executor failure', (_label, store) => {
  const facet = new IdempotencyImpl(store, { pollTimeoutMs: 100 })

  it('releases the key when the executor throws, so the same key retried runs for real', async () => {
    let runs = 0
    await expect(
      facet.handle('throws', ctx, async () => {
        runs++
        throw new Error('transient db blip')
      }),
    ).rejects.toThrow('transient db blip')
    expect(runs).toBe(1)

    const retry = await facet.handle('throws', ctx, async () => {
      runs++
      return ok(201)
    })
    expect(retry.status).toBe(201)
    expect(runs).toBe(2)
  })

  it('still caches a response the executor did return, so the release is not idempotency switched off', async () => {
    let runs = 0
    const first = await facet.handle('succeeds', ctx, async () => {
      runs++
      return ok(200 + runs)
    })
    const second = await facet.handle('succeeds', ctx, async () => {
      runs++
      return ok(200 + runs)
    })
    expect(first.status).toBe(201)
    expect(second.status).toBe(201)
    expect(runs).toBe(1)
  })

  it('hands the caller the executor error, not a store error', async () => {
    await expect(
      facet.handle('surfaces', ctx, () => Promise.reject(new AggregateError([], 'from the executor'))),
    ).rejects.toThrow('from the executor')
  })

  it('keeps the key usable after a throw and a success, one key at a time', async () => {
    for (const attempt of [1, 2, 3]) {
      await expect(
        facet.handle('repeated', ctx, () => Promise.reject(new Error(`attempt ${attempt}`))),
      ).rejects.toThrow(`attempt ${attempt}`)
    }
    expect((await facet.handle('repeated', ctx, async () => ok(204))).status).toBe(204)
  })
})

describe('IdempotencyImpl release failures and the poll loop', () => {
  it('surfaces the executor error even when releasing the claim fails, and logs the release', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const store = new MemoryIdempotency()
      store.delete = () => Promise.reject(new Error('store unreachable'))
      const facet = new IdempotencyImpl(store, { pollTimeoutMs: 50 })
      await expect(facet.handle('k', ctx, () => Promise.reject(new Error('from the executor')))).rejects.toThrow(
        'from the executor',
      )
      expect(logged.mock.calls.map(([line]) => line)).toEqual([
        '[@gentleduck/auth] idempotency could not release a failed key; a repeat answers 409:',
      ])
    } finally {
      logged.mockRestore()
    }
  })

  it('leaves a concurrent loser on the 409 path rather than running the work twice', async () => {
    const store = new MemoryIdempotency()
    const facet = new IdempotencyImpl(store, { pollTimeoutMs: 100 })
    let runs = 0
    // The winner is still inside its executor while the loser polls, so the loser must not execute.
    const winner = facet.handle('raced', ctx, async () => {
      runs++
      await new Promise((r) => setTimeout(r, 200))
      throw new Error('winner failed')
    })
    const loser = await facet.handle('raced', ctx, async () => {
      runs++
      return ok(201)
    })
    expect(loser.status).toBe(409)
    expect(runs).toBe(1)
    await expect(winner).rejects.toThrow('winner failed')
    // And once the winner has let go, the key is free again.
    const after = await facet.handle('raced', ctx, async () => {
      runs++
      return ok(201)
    })
    expect(after.status).toBe(201)
    expect(runs).toBe(2)
  })
})

describe.each(stores())('IdempotencyImpl over the %s store, once the executor has run', (_label, store) => {
  it('answers what the executor returned when the response cannot be cached, and logs it', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    const put = store.put
    try {
      store.put = () => Promise.reject(new Error('READONLY'))
      const facet = new IdempotencyImpl(store, { pollTimeoutMs: 50 })
      let runs = 0
      const charge = async () => {
        runs++
        return ok(201)
      }
      await expect(facet.handle('uncached', ctx, charge)).resolves.toMatchObject({ status: 201 })
      expect(logged.mock.calls.map(([line]) => line)).toEqual([
        '[@gentleduck/auth] idempotency could not cache a response; a repeat of its key answers 409:',
      ])
      // The claim still holds the key, so a repeat does not charge again.
      await expect(facet.handle('uncached', ctx, charge)).resolves.toMatchObject({ status: 409 })
      expect(runs).toBe(1)
    } finally {
      store.put = put
      logged.mockRestore()
    }
  })

  it.each([
    ['answers 503', async () => ok(503)],
    [
      'throws',
      async (): Promise<Idempotency.CachedResponse> => {
        throw new Error('db down')
      },
    ],
  ])('a repeat waiting on an attempt that %s runs it, rather than answering 409', async (how, fail) => {
    const facet = new IdempotencyImpl(store, { pollTimeoutMs: 2_000 })
    const key = `waiting-${how}`
    let runs = 0
    const started = Date.now()
    const first = facet
      .handle(key, ctx, async () => {
        runs++
        await new Promise((r) => setTimeout(r, 50))
        return fail()
      })
      .catch(() => null)
    const repeat = await facet.handle(key, ctx, async () => {
      runs++
      return ok(201)
    })
    await first
    expect(repeat.status).toBe(201)
    expect(runs).toBe(2)
    expect(Date.now() - started).toBeLessThan(1_000)
    // And its answer is the one the key keeps.
    await expect(facet.handle(key, ctx, async () => ok(202))).resolves.toMatchObject({ status: 201 })
  })

  it('replays a response without its Set-Cookie, in any case, keeping the other headers', async () => {
    const facet = new IdempotencyImpl(store)
    const headers = { Location: '/accounts/1', 'Set-Cookie': 'duck-sid=s; HttpOnly', 'set-cookie': 'b=1' }
    const first = await facet.handle('cookie', ctx, async () => ({ ...ok(201), headers }))
    expect(first.headers).toEqual(headers)

    const replay = await facet.handle('cookie', ctx, async () => ok(500))
    expect(replay.status).toBe(201)
    expect(replay.headers).toEqual({ Location: '/accounts/1' })
  })

  it('adds no headers to a response that had none', async () => {
    const facet = new IdempotencyImpl(store)
    await facet.handle('bare', ctx, async () => ok(201))
    expect(await facet.handle('bare', ctx, async () => ok(500))).not.toHaveProperty('headers')
  })
})
