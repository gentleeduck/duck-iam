import { beforeEach, describe, expect, it, vi } from 'vitest'
import { FakeRedis } from '~/core/drivers/redis-like'
import { InMemoryEvents } from '../events.memory'
import { RedisEvents } from '../events.redis'

describe('RedisEvents', () => {
  let redis: FakeRedis
  let bus: RedisEvents

  beforeEach(() => {
    redis = new FakeRedis()
    bus = new RedisEvents({ redis, prefix: 'test:events' })
  })

  it('emit dispatches to local handlers synchronously off the publish call', async () => {
    const handler = vi.fn()
    bus.on('session.created', handler)
    await bus.emit('session.created', {
      session: { id: 's1' } as never,
      identity: null,
    })
    expect(handler).toHaveBeenCalledOnce()
    expect(handler.mock.calls[0]![0]!.session.id).toBe('s1')
  })

  it('two RedisEvents instances on the same FakeRedis receive each other emits', async () => {
    const otherBus = new RedisEvents({ redis, prefix: 'test:events' })
    const remoteHandler = vi.fn()
    otherBus.on('signup.completed', remoteHandler)
    // Allow the lazy subscribe to register before the emit.
    await new Promise((r) => setTimeout(r, 10))
    await bus.emit('signup.completed', { identity: { id: 'u1' } as never })
    await new Promise((r) => setTimeout(r, 10))
    expect(remoteHandler).toHaveBeenCalled()
  })

  it('listenerCount tracks local subscribers', async () => {
    bus.on('lockout', vi.fn())
    bus.on('lockout', vi.fn())
    expect(bus.listenerCount('lockout')).toBe(2)
  })

  it('unsubscribe removes the handler + decrements count', async () => {
    const unsubscribe = bus.on('lockout', vi.fn())
    expect(bus.listenerCount('lockout')).toBe(1)
    unsubscribe()
    expect(bus.listenerCount('lockout')).toBe(0)
  })

  it('uses the configured prefix when composing channel names', async () => {
    const publishSpy = vi.spyOn(redis, 'publish')
    await bus.emit('lockout', { identityId: 'u1', until: 0 })
    expect(publishSpy).toHaveBeenCalledWith('test:events:lockout', expect.any(String))
  })

  it('handler that throws does not block siblings + propagates the emit', async () => {
    const stderrSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const good = vi.fn()
    bus.on('lockout', () => {
      throw new Error('boom')
    })
    bus.on('lockout', good)
    await bus.emit('lockout', { identityId: 'u1', until: 0 })
    expect(good).toHaveBeenCalled()
    stderrSpy.mockRestore()
  })

  describe('pub/sub envelope validation (hostile publisher defense)', () => {
    it('discards malformed JSON without crashing the subscriber', async () => {
      const handler = vi.fn()
      bus.on('lockout', handler)
      await new Promise((r) => setTimeout(r, 10))
      // Publish raw garbage that would have thrown JSON.parse -> uncaught
      // error out of the subscribe callback, killing the subscription.
      await redis.publish('test:events:lockout', '}')
      await redis.publish('test:events:lockout', 'not json')
      await new Promise((r) => setTimeout(r, 10))
      expect(handler).not.toHaveBeenCalled()
      // Sanity: subscription still works after the bad messages.
      await bus.emit('lockout', { identityId: 'u', until: 0 })
      expect(handler).toHaveBeenCalled()
    })

    it('discards null envelope (would have thrown TypeError on `null.from`)', async () => {
      const handler = vi.fn()
      bus.on('lockout', handler)
      await new Promise((r) => setTimeout(r, 10))
      await redis.publish('test:events:lockout', 'null')
      await new Promise((r) => setTimeout(r, 10))
      expect(handler).not.toHaveBeenCalled()
    })

    it('discards array envelope (not a plain object)', async () => {
      const handler = vi.fn()
      bus.on('lockout', handler)
      await new Promise((r) => setTimeout(r, 10))
      await redis.publish('test:events:lockout', '[1,2,3]')
      await new Promise((r) => setTimeout(r, 10))
      expect(handler).not.toHaveBeenCalled()
    })

    it('discards envelope with non-string `from`', async () => {
      const handler = vi.fn()
      bus.on('lockout', handler)
      await new Promise((r) => setTimeout(r, 10))
      await redis.publish('test:events:lockout', JSON.stringify({ from: 42, payload: { identityId: 'u', until: 0 } }))
      await new Promise((r) => setTimeout(r, 10))
      expect(handler).not.toHaveBeenCalled()
    })

    it('discards envelope with missing `payload` key', async () => {
      const handler = vi.fn()
      bus.on('lockout', handler)
      await new Promise((r) => setTimeout(r, 10))
      await redis.publish('test:events:lockout', JSON.stringify({ from: 'remote-instance' }))
      await new Promise((r) => setTimeout(r, 10))
      expect(handler).not.toHaveBeenCalled()
    })
  })
})

/**
 * `on()` subscribes to the channel once per event, guarded by `_subscriptions.has(event)` - but the
 * map is only written inside the subscribe promise's `.then()`. Two `on()` calls for one event in the
 * same tick both read an empty map and both subscribe, which is the ordinary case: handlers for one
 * event are registered together at boot.
 */
describe('RedisEvents subscribes to each channel once', () => {
  it('two handlers for one event do not open two subscriptions', async () => {
    const redis = new FakeRedis()
    const bus = new RedisEvents({ prefix: 'test:events', redis })
    const subscribeSpy = vi.spyOn(redis, 'subscribe')

    bus.on('lockout', vi.fn())
    bus.on('lockout', vi.fn())
    await new Promise((r) => setTimeout(r, 10))

    expect(subscribeSpy).toHaveBeenCalledTimes(1)
  })

  it('a remote emit reaches each local handler exactly once', async () => {
    const redis = new FakeRedis()
    const publisher = new RedisEvents({ prefix: 'test:events', redis })
    const subscriber = new RedisEvents({ prefix: 'test:events', redis })
    const first = vi.fn()
    const second = vi.fn()

    subscriber.on('lockout', first)
    subscriber.on('lockout', second)
    await new Promise((r) => setTimeout(r, 10))

    await publisher.emit('lockout', { identityId: 'u1', until: 0 })
    await new Promise((r) => setTimeout(r, 10))

    expect(first).toHaveBeenCalledTimes(1)
    expect(second).toHaveBeenCalledTimes(1)
  })

  it('unsubscribing every handler really closes the channel', async () => {
    const redis = new FakeRedis()
    const publisher = new RedisEvents({ prefix: 'test:events', redis })
    const subscriber = new RedisEvents({ prefix: 'test:events', redis })
    const handler = vi.fn()

    const offFirst = subscriber.on('lockout', vi.fn())
    const offSecond = subscriber.on('lockout', handler)
    await new Promise((r) => setTimeout(r, 10))
    offFirst()
    offSecond()
    await new Promise((r) => setTimeout(r, 10))

    await publisher.emit('lockout', { identityId: 'u1', until: 0 })
    await new Promise((r) => setTimeout(r, 10))
    expect(handler).not.toHaveBeenCalled()
    // `publish` answers the number of subscribers on the channel, which is the only public view of
    // it. The second subscribe's unsubscribe overwrote the first in the map, leaving the first
    // unreachable and open for the life of the process.
    expect(await redis.publish('test:events:lockout', '{}')).toBe(0)
  })
})

/**
 * `InMemoryEvents.emit` snapshots its handler set before dispatching, with a comment saying why: a
 * handler that subscribes or unsubscribes mid-emit must not reorder the dispatch or extend it.
 * `RedisEvents._dispatchLocal` iterates the live `Set`, and a `for...of` over a Set visits entries
 * added after the cursor - so the two implementations of one bus contract disagree about what an
 * emit is.
 */
describe('RedisEvents dispatches the handlers that were registered when the emit began', () => {
  it('a handler subscribed during dispatch does not receive the in-flight event', async () => {
    const redis = new FakeRedis()
    const bus = new RedisEvents({ prefix: 'test:events', redis })
    const late = vi.fn()
    bus.on('lockout', () => {
      bus.on('lockout', late)
    })

    await bus.emit('lockout', { identityId: 'u1', until: 0 })

    expect(late).not.toHaveBeenCalled()
  })

  it('a handler unsubscribed by a sibling mid-emit still receives that event', async () => {
    const redis = new FakeRedis()
    const bus = new RedisEvents({ prefix: 'test:events', redis })
    const second = vi.fn()
    let offSecond: () => void = () => undefined
    bus.on('lockout', () => {
      offSecond()
    })
    offSecond = bus.on('lockout', second)

    await bus.emit('lockout', { identityId: 'u1', until: 0 })

    expect(second).toHaveBeenCalledTimes(1)
  })

  it('matches InMemoryEvents, which is the same contract', async () => {
    const memory = new InMemoryEvents()
    const late = vi.fn()
    memory.on('lockout', () => {
      memory.on('lockout', late)
    })
    await memory.emit('lockout', { identityId: 'u1', until: 0 })

    expect(late).not.toHaveBeenCalled()
  })
})

/**
 * The class docstring promises every `on()` subscriber across the fleet receives each emit. A rejected
 * `publish` was answered with `() => 0`, so the fan-out could be down indefinitely and `emit` still
 * resolved as success with nothing anywhere recording it — the one failure in this file that said
 * nothing, where a failed subscribe retries and a throwing listener is logged.
 */
describe('RedisEvents reports a fan-out it could not perform', () => {
  const refusing = () => {
    const redis = new FakeRedis()
    Object.assign(redis, {
      publish: async () => {
        throw new Error('NOPUBSUB')
      },
    })
    return new RedisEvents({ prefix: 'test:events', redis })
  }

  it('names the event it could not publish', async () => {
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    await refusing().emit('session.created', { identity: null, session: { id: 's1' } as never })
    expect(stderr).toHaveBeenCalledOnce()
    expect(String(stderr.mock.calls[0]?.[0])).toContain('session.created')
    stderr.mockRestore()
  })

  it('still resolves and still runs local handlers, since those already fired', async () => {
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const bus = refusing()
    const handler = vi.fn()
    bus.on('session.created', handler)
    await expect(
      bus.emit('session.created', { identity: null, session: { id: 's1' } as never }),
    ).resolves.toBeUndefined()
    expect(handler).toHaveBeenCalledOnce()
    stderr.mockRestore()
  })
})
