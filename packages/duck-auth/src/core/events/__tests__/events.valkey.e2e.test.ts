/**
 * E2E: `valkeyEvents`/`valkeyPubSubAdapter` against a REAL server.
 *
 * `events.redis.e2e.test.ts` covers the `RedisEvents` bus contract itself. This
 * proves `valkeyEvents` correctly wires a `{ cmd, sub }` ioredis connection pair
 * into that bus: pub/sub fan-out is a claim about real sockets that no in-process
 * double can stand in for.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeyEvents } from '~/core/events/events.valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

/** Delivery is asynchronous over a socket; poll rather than guess a sleep. */
async function until(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('condition not met before timeout')
}

suite('E2E valkeyEvents (real server pub/sub)', () => {
  const connections: Redis[] = []
  let prefix: string

  function connect(): Redis {
    const r = new Redis(URL as string, { lazyConnect: false, maxRetriesPerRequest: 2 })
    connections.push(r)
    return r
  }

  /** A bus as a separate instance would build it: own connections, shared server. */
  function bus() {
    return valkeyEvents({ prefix, cmd: connect(), sub: connect() })
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

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-valkey-remote' })

    await until(() => seen.includes('sess-valkey-remote'))
  })

  it('the emitting instance does not see a loopback copy of its own emit twice', async () => {
    const self = bus()
    const seen: string[] = []
    self.on('session.revoked', (p) => {
      seen.push(p.sessionId)
    })
    await new Promise((r) => setTimeout(r, 250))

    await self.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-valkey-local' })
    await new Promise((r) => setTimeout(r, 500))

    expect(seen.filter((s) => s === 'sess-valkey-local')).toHaveLength(1)
  })
})
