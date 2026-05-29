/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { RedisEvents } from '../events'
import { FakeRedis } from '../redis-like'

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
})
