/**
 * E2E: RedisEvents against a REAL Redis.
 *
 * The bus exists so a `session.revoked` on one instance reaches listeners on the
 * others. That is a claim about pub/sub delivery between separate connections,
 * which no in-process double can test: a fake either delivers everything locally
 * (hiding a broken publish) or nothing (hiding a broken subscribe).
 *
 * `revocation.multiprocess.e2e` proves the same path across real OS processes.
 * This suite covers the bus contract itself: fan-out, loopback dedup, channel
 * isolation, and unsubscribe.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import type { ValkeyClient, ValkeySubscriberClient } from '~/adapters/valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'
import { RedisEvents } from '../events.redis'
import { valkeyPubSubAdapter } from '../events.valkey'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

/** Pub/sub needs its own connection: a subscribed ioredis client refuses commands. */
function eventsClient(cmd: Redis, sub: Redis): RedisEvents.Client {
  return valkeyPubSubAdapter(
    cmd as unknown as ValkeyClient.Me & { publish(channel: string, message: string): Promise<number> },
    sub as unknown as ValkeySubscriberClient.Me,
  )
}

/** Delivery is asynchronous over a socket; poll rather than guess a sleep. */
async function until(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('condition not met before timeout')
}

suite('E2E RedisEvents (real Redis pub/sub)', () => {
  const connections: Redis[] = []
  let prefix: string

  function connect(): Redis {
    const r = new Redis(URL as string, { lazyConnect: false, maxRetriesPerRequest: 2 })
    connections.push(r)
    return r
  }

  /** A bus as a separate instance would build it: own connections, shared server. */
  function bus(): RedisEvents {
    return new RedisEvents({ prefix, redis: eventsClient(connect(), connect()) })
  }

  beforeAll(() => {
    prefix = e2ePrefix()
  })

  afterAll(async () => {
    const cleanup = connect()
    await dropPrefix(cleanup, prefix)
    await Promise.all(connections.map((c) => c.quit().catch(() => undefined)))
  })

  it('an emit on one instance reaches a listener on another', async () => {
    const publisher = bus()
    const listener = bus()
    const seen: string[] = []
    listener.on('session.revoked', (p) => {
      seen.push(p.sessionId)
    })
    // Subscribe is established lazily; let it settle or the publish lands in a void.
    await new Promise((r) => setTimeout(r, 250))

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
    await new Promise((r) => setTimeout(r, 250))

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-fanout' })

    await until(() => seenA.includes('sess-fanout') && seenB.includes('sess-fanout'))
  })

  it('the emitting instance runs its own handler exactly once', async () => {
    // Local handlers fire off the publish call AND the instance is subscribed to
    // its own channel, so the instance id has to suppress the loopback copy.
    const self = bus()
    const handler = vi.fn()
    self.on('session.revoked', handler)
    await new Promise((r) => setTimeout(r, 250))

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
    await new Promise((r) => setTimeout(r, 250))

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-isolated' })

    await until(() => revoked.mock.calls.length === 1)
    expect(created).not.toHaveBeenCalled()
  })

  it('unsubscribing stops delivery', async () => {
    const publisher = bus()
    const listener = bus()
    const handler = vi.fn()
    const off = listener.on('session.revoked', handler)
    await new Promise((r) => setTimeout(r, 250))

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'before' })
    await until(() => handler.mock.calls.length === 1)

    off()
    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'after' })
    await new Promise((r) => setTimeout(r, 500))

    expect(handler).toHaveBeenCalledTimes(1)
  })
})
