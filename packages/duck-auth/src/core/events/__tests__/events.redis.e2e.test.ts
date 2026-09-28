/** E2E: RedisEvents against a REAL Redis. */
import Redis from 'ioredis'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { RedisEvents } from '../events.redis'
import { valkeyPubSubAdapter } from '../events.valkey'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

/** Pub/sub needs its own connection: a subscribed ioredis client refuses commands. */
function eventsClient(cmd: Redis, sub: Redis): RedisEvents.Client {
  return valkeyPubSubAdapter(cmd, sub)
}

/** Delivery is asynchronous over a socket; poll rather than guess a sleep. */
async function until(predicate: () => boolean | Promise<boolean>, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('condition not met before timeout')
}

suite('E2E RedisEvents (real Redis pub/sub)', () => {
  const connections: Redis[] = []
  const prefixes: string[] = []
  let prefix: string

  function connect(): Redis {
    const r = new Redis(URL, { lazyConnect: false, maxRetriesPerRequest: 2 })
    connections.push(r)
    return r
  }

  /** A bus as a separate instance would build it: own connections, shared server. */
  function bus(): RedisEvents {
    return new RedisEvents({ prefix, redis: eventsClient(connect(), connect()) })
  }

  /** Waits until `count` buses hold `event`'s channel; a publish before that lands in a void. */
  async function subscribed(event: string, count = 1): Promise<void> {
    const cmd = connect()
    await until(async () => Number((await cmd.pubsub('NUMSUB', `${prefix}:${event}`))[1]) >= count)
  }

  // Per test, so a listener an earlier test left subscribed does not count toward this one's.
  beforeEach(() => {
    prefix = e2ePrefix()
    prefixes.push(prefix)
  })

  afterAll(async () => {
    const cleanup = connect()
    for (const p of prefixes) await dropPrefix(cleanup, p)
    await Promise.all(connections.map((c) => c.quit().catch(() => undefined)))
  })

  it('an emit on one instance reaches a listener on another', async () => {
    const publisher = bus()
    const listener = bus()
    const seen: string[] = []
    listener.on('session.revoked', (p) => {
      seen.push(p.sessionId)
    })
    await subscribed('session.revoked')

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-remote' })

    await until(() => seen.includes('sess-remote'))
  })

  it('every subscribed instance receives the same emit', async () => {
    const publisher = bus()
    const a = bus()
    const b = bus()
    const seenA: string[] = []
    const seenB: string[] = []
    a.on('session.revoked', (p) => {
      seenA.push(p.sessionId)
    })
    b.on('session.revoked', (p) => {
      seenB.push(p.sessionId)
    })
    await subscribed('session.revoked', 2)

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-fanout' })

    await until(() => seenA.includes('sess-fanout') && seenB.includes('sess-fanout'))
  })

  it('the emitting instance runs its own handler exactly once', async () => {
    // Local handlers fire off the publish call AND the instance is subscribed to
    // its own channel, so the instance id has to suppress the loopback copy.
    const self = bus()
    const handler = vi.fn()
    self.on('session.revoked', handler)
    await subscribed('session.revoked')

    await self.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-local' })
    await new Promise((r) => setTimeout(r, 500))

    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('a listener on one event never sees another', async () => {
    const publisher = bus()
    const listener = bus()
    const revoked = vi.fn()
    const created = vi.fn()
    listener.on('session.revoked', revoked)
    listener.on('session.created', created)
    await subscribed('session.revoked')
    await subscribed('session.created')

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-isolated' })

    await until(() => revoked.mock.calls.length === 1)
    expect(created).not.toHaveBeenCalled()
  })

  it('unsubscribing stops delivery', async () => {
    const publisher = bus()
    const listener = bus()
    const handler = vi.fn()
    const off = listener.on('session.revoked', handler)
    await subscribed('session.revoked')

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'before' })
    await until(() => handler.mock.calls.length === 1)

    off()
    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'after' })
    await new Promise((r) => setTimeout(r, 500))

    expect(handler).toHaveBeenCalledTimes(1)
  })
})
