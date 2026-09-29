/** Every server attaches its own deliverer, so a webhook goes out once, from the server that emitted. */
import { describe, expect, it, vi } from 'vitest'
import { FakeRedis } from '~/core/drivers/redis-like'
import { InMemoryEvents, RedisEvents } from '~/core/events'
import { WebhookDeliverer } from '../index'

const LOCKOUT = { identityId: 'u', until: 0 }

/** Lets a subscribe or a delivery land. */
async function settle(): Promise<void> {
  for (let i = 0; i < 4; i++) await new Promise((resolve) => setTimeout(resolve, 0))
}

/** One server: its bus, a deliverer attached to it, and what that deliverer posted. */
function makeServer(redis: FakeRedis) {
  const bus = new RedisEvents({ redis, prefix: 'test:events' })
  const posted: string[] = []
  const deliverer = new WebhookDeliverer({
    backoffMs: 0,
    endpoints: [{ events: '*', secret: 'shhh', url: 'https://hooks.example.com/duck' }],
    fetch: async (_url, init = {}) => {
      posted.push(String(init.body))
      return new Response('', { status: 200 })
    },
  })
  deliverer.attach(bus)
  return { bus, deliverer, posted }
}

describe('WebhookDeliverer.attach on a fleet', () => {
  it('posts once per emit, from the server that emitted', async () => {
    const redis = new FakeRedis()
    const [a, b] = [makeServer(redis), makeServer(redis)]
    const reachedB = vi.fn()
    b.bus.on('lockout', reachedB)
    await settle()

    await a.bus.emit('lockout', LOCKOUT)
    await settle()
    await Promise.all([a.deliverer.drain(), b.deliverer.drain()])

    expect(reachedB).toHaveBeenCalledOnce()
    expect(a.posted).toHaveLength(1)
    expect(b.posted).toHaveLength(0)

    await b.bus.emit('lockout', LOCKOUT)
    await settle()
    await Promise.all([a.deliverer.drain(), b.deliverer.drain()])
    expect(a.posted).toHaveLength(1)
    expect(b.posted).toHaveLength(1)
  })

  it('registers as origin, so it opens no channel', async () => {
    const redis = new FakeRedis()
    const subscribe = vi.spyOn(redis, 'subscribe')
    makeServer(redis)
    await settle()
    expect(subscribe).not.toHaveBeenCalled()
  })

  it('posts nothing for an event another service published straight to Redis', async () => {
    const redis = new FakeRedis()
    const a = makeServer(redis)
    const reachedA = vi.fn()
    a.bus.on('authz.revoked', reachedA)
    await settle()

    await redis.publish(
      'test:events:authz.revoked',
      JSON.stringify({ from: 'iam-service', payload: { at: 0, identityId: 'u' } }),
    )
    await settle()
    await a.deliverer.drain()

    expect(reachedA).toHaveBeenCalledOnce()
    expect(a.posted).toHaveLength(0)
  })

  it('leaves an in-process bus holding no fleet handler', () => {
    const bus = new InMemoryEvents()
    new WebhookDeliverer({
      endpoints: [{ events: '*', secret: 'shhh', url: 'https://hooks.example.com/duck' }],
      fetch: async () => new Response(),
    }).attach(bus)
    expect(bus.fleetEvents()).toEqual([])
  })
})
