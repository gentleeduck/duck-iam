/** E2E: `valkeyEvents`/`valkeyPubSubAdapter` against a REAL server. */
import Redis, { type RedisOptions } from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeyEvents } from '~/core/events/events.valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const URL = redisUrl() ?? ''
const suite = URL ? describe : describe.skip

/** Delivery is asynchronous over a socket; poll rather than guess a sleep. */
async function until(predicate: () => boolean | Promise<boolean>, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('condition not met before timeout')
}

suite('E2E valkeyEvents (real server pub/sub)', () => {
  const connections: Redis[] = []
  let prefix: string
  let admin: Redis

  function connect(opts: RedisOptions = {}): Redis {
    const r = new Redis(URL, { lazyConnect: false, maxRetriesPerRequest: 2, ...opts })
    connections.push(r)
    return r
  }

  /** A bus as a separate instance would build it: own connections, shared server. */
  function bus() {
    return valkeyEvents({ prefix, cmd: connect(), sub: connect() })
  }

  /** Connections the server has subscribed to the channel `session.revoked` is published on. */
  async function subscribers(): Promise<number> {
    const [, count] = await admin.pubsub('NUMSUB', `${prefix}:session.revoked`)
    return Number(count)
  }

  beforeAll(() => {
    prefix = e2ePrefix()
    admin = connect()
  })

  afterAll(async () => {
    await dropPrefix(admin, prefix)
    await Promise.all(connections.map((c) => c.quit().catch(() => undefined)))
  })

  it('an emit on one instance reaches a listener on another', async () => {
    const publisher = bus()
    const listener = bus()
    const seen: string[] = []
    const before = await subscribers()
    listener.on('session.revoked', (p) => {
      seen.push(p.sessionId)
    })
    // Subscribed lazily: wait for the server to count it, or the publish lands in a void.
    await until(async () => (await subscribers()) > before)

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-valkey-remote' })

    await until(() => seen.includes('sess-valkey-remote'))
  })

  it('the emitting instance does not see a loopback copy of its own emit twice', async () => {
    const self = bus()
    const seen: string[] = []
    const before = await subscribers()
    self.on('session.revoked', (p) => {
      seen.push(p.sessionId)
    })
    // Subscribed first, or no loopback copy could arrive and the count below proves nothing.
    await until(async () => (await subscribers()) > before)

    await self.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-valkey-local' })
    await new Promise((r) => setTimeout(r, 500))

    expect(seen.filter((s) => s === 'sess-valkey-local')).toHaveLength(1)
  })

  it('a subscribe the connection refused leaves no listener, so the retry hears a remote emit once', async () => {
    const publisher = bus()
    // Not connected yet and not queueing, so the first SUBSCRIBE is refused outright.
    const sub = connect({ enableOfflineQueue: false, lazyConnect: true })
    const listener = valkeyEvents({ cmd: connect(), prefix, sub })
    const seen: string[] = []
    const before = await subscribers()
    listener.on('session.revoked', (p) => {
      seen.push(p.sessionId)
    })
    await until(() => sub.status === 'ready')
    listener.on('session.revoked', () => {})
    await until(async () => (await subscribers()) > before)

    await publisher.emit('session.revoked', { identityId: 'i-1', sessionId: 'sess-valkey-retry' })
    await until(() => seen.includes('sess-valkey-retry'))
    await new Promise((r) => setTimeout(r, 500))

    expect(seen.filter((s) => s === 'sess-valkey-retry')).toHaveLength(1)
  })
})
