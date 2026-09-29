/** E2E: `origin` and `fleet` delivery over a real server, where a message arrives off the subscriber's socket. */
import { AsyncLocalStorage } from 'node:async_hooks'
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { Events } from '~/core/events/events.types'
import { valkeyEvents } from '~/core/events/events.valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const URL = redisUrl()
const suite = URL ? describe : describe.skip
const LOCKOUT = { identityId: 'ident-1', until: 0 }
const ORIGIN: Events.OnOptions = { delivery: 'origin' }

/** Delivery is asynchronous over a socket; poll rather than guess a sleep. */
async function until(predicate: () => boolean | Promise<boolean>, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('condition not met before timeout')
}

suite('E2E origin and fleet delivery (real server pub/sub)', () => {
  const connections: Redis[] = []
  let prefix: string
  let admin: Redis
  let seq = 0

  function connect(): Redis {
    const r = new Redis(URL, { maxRetriesPerRequest: 2 })
    connections.push(r)
    return r
  }

  /** `n` servers on a channel prefix of their own, and how many connections the server holds on `lockout`. */
  function fleet(n: number) {
    const p = `${prefix}:${++seq}`
    return {
      servers: Array.from({ length: n }, () => valkeyEvents({ cmd: connect(), prefix: p, sub: connect() })),
      subscribers: async () => Number((await admin.pubsub('NUMSUB', `${p}:lockout`))[1]),
    }
  }

  beforeAll(() => {
    prefix = e2ePrefix()
    admin = connect()
  })

  afterAll(async () => {
    await dropPrefix(admin, prefix)
    await Promise.all(connections.map((c) => c.quit().catch(() => undefined)))
  })

  it('runs an origin handler once, on the emitter, in its context, and a fleet handler on the other server outside it', async () => {
    const { servers, subscribers } = fleet(2)
    const [a, b] = servers
    if (!a || !b) throw new Error('two servers')
    const als = new AsyncLocalStorage<string>()
    const seen = new Map<string, string | undefined>()
    a.on('lockout', () => void seen.set('originA', als.getStore()), ORIGIN)
    b.on('lockout', () => void seen.set('originB', als.getStore()), ORIGIN)
    a.on('lockout', () => void seen.set('fleetA', als.getStore()))
    b.on('lockout', () => void seen.set('fleetB', als.getStore()))
    await until(async () => (await subscribers()) === 2)

    await als.run('req-1', () => a.emit('lockout', LOCKOUT))
    await until(() => seen.has('fleetB'))
    // Room for a stray copy to land before the map is judged.
    await new Promise((r) => setTimeout(r, 300))

    expect(seen).toEqual(
      new Map([
        ['originA', 'req-1'],
        ['fleetA', 'req-1'],
        ['fleetB', undefined],
      ]),
    )
  })

  it('writes an origin handler once per emit across three servers', async () => {
    const { servers, subscribers } = fleet(3)
    const writes: number[] = []
    const clears: number[] = []
    for (const [i, s] of servers.entries()) {
      s.on('lockout', () => void writes.push(i), ORIGIN)
      s.on('lockout', () => void clears.push(i))
    }
    await until(async () => (await subscribers()) === 3)

    for (const s of servers) await s.emit('lockout', LOCKOUT)
    await until(() => clears.length === 9)
    await new Promise((r) => setTimeout(r, 300))

    expect(writes).toEqual([0, 1, 2])
    expect(clears.sort()).toEqual([0, 0, 0, 1, 1, 1, 2, 2, 2])
  })

  it('holds no channel for origin handlers, and closes it with the last fleet one while they keep running', async () => {
    const { servers, subscribers } = fleet(1)
    const [a] = servers
    if (!a) throw new Error('one server')
    let originRuns = 0
    a.on('lockout', () => void originRuns++, ORIGIN)
    await new Promise((r) => setTimeout(r, 200))
    expect(await subscribers()).toBe(0)

    const off = a.on('lockout', () => {})
    await until(async () => (await subscribers()) === 1)

    off()
    await until(async () => (await subscribers()) === 0)
    await a.emit('lockout', LOCKOUT)
    expect(originRuns).toBe(1)
  })

  it('publishes an emit from a server holding no fleet handler', async () => {
    const { servers, subscribers } = fleet(2)
    const [a, b] = servers
    if (!a || !b) throw new Error('two servers')
    let reached = 0
    b.on('lockout', () => void reached++)
    await until(async () => (await subscribers()) === 1)

    await a.emit('lockout', LOCKOUT)
    await until(() => reached === 1)
  })
})
