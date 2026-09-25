/** The valkey backend, in-process. */

import { describe, expect, it, vi } from 'vitest'
import { FakeRedis } from '~/core/drivers/redis-like'
import { valkeyAdapter } from '~/core/drivers/valkey-like'
import { valkeyEvents } from '~/core/events/events.valkey'
import { valkeySessionImpl } from '~/core/sessions/sessions.valkey'
import { valkeyDPoPNonceStore } from '~/core/transport/dpop-nonce.valkey'
import { FakeValkey, FakeValkeySubscriber } from '~/test/fake-valkey'
import { runSessionStoreCompliance } from '~/test/store-compliance'

describe('valkeyAdapter translation', () => {
  /**
   * The whole reason this file exists: ioredis takes options variadically, so a client passed
   * straight through drops the TTL and the NX guard without throwing. Each case asserts the
   * effect, not the arguments - an adapter that emitted the right tokens and a store that ignored
   * them would read identically at the call site.
   */
  it('carries EX through as a TTL rather than dropping it', async () => {
    const client = valkeyAdapter(new FakeValkey())
    await client.set('live', 'v', { ex: 60 })
    // Every write goes through the adapter, including this one: reaching past it to the fake would
    // assert the fake honours a TTL and say nothing about whether the translation passed one on.
    await client.set('stale', 'v', { ex: -1 })

    expect(await client.get('live')).toBe('v')
    expect(await client.get('stale')).toBeNull()
  })

  it('carries NX through, so a second write is refused', async () => {
    const client = valkeyAdapter(new FakeValkey())
    expect(await client.set('k', 'first', { nx: true })).toBe('OK')
    expect(await client.set('k', 'second', { nx: true })).toBeNull()
    expect(await client.get('k')).toBe('first')
  })

  it('sets with no options at all, which must not become an EX of undefined', async () => {
    const client = valkeyAdapter(new FakeValkey())
    expect(await client.set('k', 'v')).toBe('OK')
    expect(await client.get('k')).toBe('v')
  })

  it('carries the LIMIT pair through to zrangebyscore', async () => {
    const client = valkeyAdapter(new FakeValkey())
    await client.zadd('z', 1, 'one')
    await client.zadd('z', 2, 'two')
    await client.zadd('z', 3, 'three')

    expect(await client.zrangebyscore('z', '-inf', '+inf', { limit: { count: 2, offset: 1 } })).toEqual([
      'two',
      'three',
    ])
    expect(await client.zrangebyscore('z', '-inf', '+inf')).toEqual(['one', 'two', 'three'])
  })

  it('reports a re-scored member as 0, matching every other client', async () => {
    const client = valkeyAdapter(new FakeValkey())
    expect(await client.zadd('z', 1, 'm')).toBe(1)
    expect(await client.zadd('z', 2, 'm')).toBe(0)
  })
})

describe('valkeySessionImpl compliance matrix', () => {
  runSessionStoreCompliance(() => valkeySessionImpl({ prefix: 'v', redis: new FakeValkey() }))
})

describe('valkeyDPoPNonceStore', () => {
  it('claims a jti once, which is the SET NX the adapter has to carry', async () => {
    const store = valkeyDPoPNonceStore({ redis: new FakeValkey() })

    expect(await store.recordSeen('jti-1', 60_000)).toBe(true)
    // A dropped NX makes this true as well, and replay protection is gone with no error anywhere.
    expect(await store.recordSeen('jti-1', 60_000)).toBe(false)
  })
})

describe('valkeyEvents', () => {
  it('carries an emit from one bus to another across the pair', async () => {
    const redis = new FakeRedis()
    const cfg = { cmd: new FakeValkey(redis), sub: new FakeValkeySubscriber(redis) }
    const emitter = valkeyEvents(cfg)
    const listener = valkeyEvents({ cmd: new FakeValkey(redis), sub: new FakeValkeySubscriber(redis) })
    const handler = vi.fn()

    listener.on('signup.completed', handler)
    // `on` subscribes lazily off the call, as the redis suite next door also waits for.
    await new Promise((resolve) => setTimeout(resolve, 10))
    await emitter.emit('signup.completed', { identity: { id: 'u1' } as never })
    await new Promise((resolve) => setTimeout(resolve, 10))

    expect(handler).toHaveBeenCalledOnce()
  })

  it('filters by channel, so a handler never sees another event name', async () => {
    const redis = new FakeRedis()
    const emitter = valkeyEvents({ cmd: new FakeValkey(redis), sub: new FakeValkeySubscriber(redis) })
    const listener = valkeyEvents({ cmd: new FakeValkey(redis), sub: new FakeValkeySubscriber(redis) })
    const handler = vi.fn()

    listener.on('signup.completed', handler)
    await new Promise((resolve) => setTimeout(resolve, 10))
    await emitter.emit('lockout', { identityId: 'u1' } as never)
    await new Promise((resolve) => setTimeout(resolve, 10))

    expect(handler).not.toHaveBeenCalled()
  })
})
