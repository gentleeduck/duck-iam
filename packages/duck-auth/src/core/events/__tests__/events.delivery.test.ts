/** `on(event, handler, { delivery })`: an `origin` handler runs once, on the server that emitted, inside its
 *  async context; a `fleet` handler runs on every server. */
import { AsyncLocalStorage, AsyncResource } from 'node:async_hooks'
import { describe, expect, expectTypeOf, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { FakeRedis } from '~/core/drivers/redis-like'
import { createTest } from '~/test'
import { withAuditStamping } from '../events.audit'
import { InMemoryEvents } from '../events.memory'
import { RedisEvents } from '../events.redis'
import type { Events } from '../events.types'

type P = { username: string; email: string }

/** Runs each message in the context it subscribed in, as a real client's socket does, and counts open channels. */
class SocketRedis extends FakeRedis {
  readonly open = new Map<string, number>()
  subscribes = 0

  override async subscribe(
    channel: string,
    onMessage: (channel: string, message: string) => void | Promise<void>,
  ): Promise<() => Promise<void>> {
    this.subscribes++
    this.open.set(channel, (this.open.get(channel) ?? 0) + 1)
    const unsubscribe = await super.subscribe(channel, AsyncResource.bind(onMessage))
    return async () => {
      this.open.set(channel, (this.open.get(channel) ?? 0) - 1)
      await unsubscribe()
    }
  }
}

const CHANNEL = 'test:events:lockout'
const LOCKOUT = { identityId: 'ident-1', until: 0 }
const ORIGIN: Events.OnOptions = { delivery: 'origin' }

const server = (redis: FakeRedis) => new RedisEvents({ redis, prefix: 'test:events' })

/** Lets a subscribe, a teardown or a delivery land. */
async function settle(): Promise<void> {
  for (let i = 0; i < 4; i++) await new Promise((resolve) => setTimeout(resolve, 0))
}

/** The memory adapter's facets, with a `withClient` so `withTransaction` can bind them. */
function joinable(adapter = new MemoryAdapter<P>()) {
  const bag = { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions }
  return { ...bag, withClient: () => bag }
}

/** Keeps the bus a bound engine hands its providers. */
class BusProbe {
  readonly id = 'probe'
  readonly kind = 'probe'
  readonly seen: Events.IBus[] = []

  withClient(_stores: unknown, events: Events.IBus): null {
    this.seen.push(events)
    return null
  }
}

describe('RedisEvents delivery', () => {
  it('runs an origin handler once, on the emitter, and a fleet handler on every server', async () => {
    const redis = new SocketRedis()
    const [a, b] = [server(redis), server(redis)]
    const originA = vi.fn()
    const originB = vi.fn()
    const fleetA = vi.fn()
    const fleetB = vi.fn()
    a.on('lockout', originA, ORIGIN)
    b.on('lockout', originB, ORIGIN)
    a.on('lockout', fleetA)
    b.on('lockout', fleetB, { delivery: 'fleet' })
    await settle()

    await a.emit('lockout', LOCKOUT)
    await settle()

    expect(originA).toHaveBeenCalledOnce()
    expect(originA).toHaveBeenCalledWith(LOCKOUT)
    expect(originB).not.toHaveBeenCalled()
    expect(fleetA).toHaveBeenCalledOnce()
    expect(fleetB).toHaveBeenCalledOnce()
    expect(fleetB).toHaveBeenCalledWith(LOCKOUT)
  })

  it('writes an origin handler once per emit across three servers, whichever emits', async () => {
    const redis = new SocketRedis()
    const servers = [server(redis), server(redis), server(redis)]
    const writes: number[] = []
    const clears: number[] = []
    for (const [i, s] of servers.entries()) {
      s.on('lockout', () => void writes.push(i), ORIGIN)
      s.on('lockout', () => void clears.push(i))
    }
    await settle()

    for (const s of servers) await s.emit('lockout', LOCKOUT)
    await settle()

    expect(writes).toEqual([0, 1, 2])
    expect(clears.sort()).toEqual([0, 0, 0, 1, 1, 1, 2, 2, 2])
  })

  it("hands an origin handler the emitter's async context, and a fleet handler on another server none", async () => {
    const redis = new SocketRedis()
    const [a, b] = [server(redis), server(redis)]
    const als = new AsyncLocalStorage<string>()
    const seen = new Map<string, string | undefined>()
    a.on('lockout', () => void seen.set('originA', als.getStore()), ORIGIN)
    a.on('lockout', () => void seen.set('fleetA', als.getStore()))
    b.on('lockout', () => void seen.set('fleetB', als.getStore()))
    await settle()

    await als.run('req-1', () => a.emit('lockout', LOCKOUT))
    await settle()

    expect(seen).toEqual(
      new Map([
        ['originA', 'req-1'],
        ['fleetA', 'req-1'],
        ['fleetB', undefined],
      ]),
    )
  })

  it('opens no channel for origin handlers, and one for the first fleet handler', async () => {
    const redis = new SocketRedis()
    const a = server(redis)
    a.on('lockout', vi.fn(), ORIGIN)
    a.on('lockout', vi.fn(), ORIGIN)
    await settle()
    expect(redis.subscribes).toBe(0)

    a.on('lockout', vi.fn())
    a.on('lockout', vi.fn())
    await settle()
    expect(redis.subscribes).toBe(1)
    expect(redis.open.get(CHANNEL)).toBe(1)
  })

  it('closes the channel with the last fleet handler while origin handlers keep running', async () => {
    const redis = new SocketRedis()
    const a = server(redis)
    const origin = vi.fn()
    a.on('lockout', origin, ORIGIN)
    const first = a.on('lockout', vi.fn())
    const last = a.on('lockout', vi.fn())
    await settle()

    first()
    await settle()
    expect(redis.open.get(CHANNEL)).toBe(1)

    last()
    await settle()
    expect(redis.open.get(CHANNEL)).toBe(0)

    await a.emit('lockout', LOCKOUT)
    expect(origin).toHaveBeenCalledOnce()
  })

  it('reopens the channel when a fleet handler comes back', async () => {
    const redis = new SocketRedis()
    const [a, b] = [server(redis), server(redis)]
    a.on('lockout', vi.fn(), ORIGIN)
    a.on('lockout', vi.fn())()
    await settle()
    expect(redis.open.get(CHANNEL)).toBe(0)

    const fleet = vi.fn()
    a.on('lockout', fleet)
    await settle()
    expect(redis.subscribes).toBe(2)
    expect(redis.open.get(CHANNEL)).toBe(1)

    await b.emit('lockout', LOCKOUT)
    await settle()
    expect(fleet).toHaveBeenCalledOnce()
  })

  it('does not reopen the channel for an origin handler added while the last fleet one is torn down', async () => {
    const redis = new SocketRedis()
    const a = server(redis)
    const off = a.on('lockout', vi.fn())
    await settle()

    off()
    a.on('lockout', vi.fn(), ORIGIN)
    await settle()

    expect(redis.subscribes).toBe(1)
    expect(redis.open.get(CHANNEL)).toBe(0)
  })

  it('keeps the channel open when an origin handler is removed', async () => {
    const redis = new SocketRedis()
    const [a, b] = [server(redis), server(redis)]
    const offOrigin = a.on('lockout', vi.fn(), ORIGIN)
    const fleet = vi.fn()
    a.on('lockout', fleet)
    await settle()

    offOrigin()
    await settle()
    expect(redis.open.get(CHANNEL)).toBe(1)

    await b.emit('lockout', LOCKOUT)
    await settle()
    expect(fleet).toHaveBeenCalledOnce()
  })

  it('publishes every emit, with or without a fleet handler on the emitter', async () => {
    const redis = new SocketRedis()
    const [a, b] = [server(redis), server(redis)]
    const publish = vi.spyOn(redis, 'publish')
    const remote = vi.fn()
    b.on('lockout', remote)
    await settle()

    await a.emit('lockout', LOCKOUT)
    a.on('lockout', vi.fn(), ORIGIN)
    await a.emit('lockout', LOCKOUT)
    await settle()

    expect(publish).toHaveBeenCalledTimes(2)
    expect(publish).toHaveBeenNthCalledWith(1, CHANNEL, expect.any(String))
    expect(publish).toHaveBeenNthCalledWith(2, CHANNEL, expect.any(String))
    expect(remote).toHaveBeenCalledTimes(2)
  })

  it('runs the origin handlers when the publish fails', async () => {
    const redis = new SocketRedis()
    const a = server(redis)
    vi.spyOn(redis, 'publish').mockRejectedValue(new Error('down'))
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const origin = vi.fn()
    a.on('lockout', origin, ORIGIN)

    await expect(a.emit('lockout', LOCKOUT)).resolves.toBeUndefined()

    expect(origin).toHaveBeenCalledOnce()
    expect(stderr).toHaveBeenCalledWith(
      '[@gentleduck/auth] RedisEvents could not publish "lockout" to the fleet:',
      expect.any(Error),
    )
    stderr.mockRestore()
  })

  it('runs no handler for its own echo', async () => {
    const redis = new SocketRedis()
    const a = server(redis)
    const origin = vi.fn()
    const fleet = vi.fn()
    a.on('lockout', origin, ORIGIN)
    a.on('lockout', fleet)
    await settle()

    await a.emit('lockout', LOCKOUT)
    await settle()

    expect(origin).toHaveBeenCalledOnce()
    expect(fleet).toHaveBeenCalledOnce()
  })

  it('does not subscribe for an origin handler after a failed subscribe', async () => {
    const redis = new SocketRedis()
    const a = server(redis)
    const subscribe = vi.spyOn(redis, 'subscribe').mockRejectedValueOnce(new Error('down'))
    a.on('lockout', vi.fn())
    await settle()

    a.on('lockout', vi.fn(), ORIGIN)
    await settle()
    expect(subscribe).toHaveBeenCalledOnce()

    a.on('lockout', vi.fn())
    await settle()
    expect(subscribe).toHaveBeenCalledTimes(2)
  })
})

describe.each([
  ['RedisEvents', () => new RedisEvents({ redis: new FakeRedis() })],
  ['InMemoryEvents', () => new InMemoryEvents()],
])('%s handler sets', (_name, make) => {
  it('counts both kinds in listenerCount', () => {
    const bus = make()
    bus.on('lockout', vi.fn(), ORIGIN)
    const off = bus.on('lockout', vi.fn())
    expect(bus.listenerCount('lockout')).toBe(2)

    off()
    expect(bus.listenerCount('lockout')).toBe(1)
  })

  it('keeps one function registered as both kinds as two registrations', async () => {
    const bus = make()
    const handler = vi.fn()
    const offOrigin = bus.on('lockout', handler, ORIGIN)
    bus.on('lockout', handler)
    await bus.emit('lockout', LOCKOUT)
    expect(handler).toHaveBeenCalledTimes(2)

    offOrigin()
    await bus.emit('lockout', LOCKOUT)
    expect(handler).toHaveBeenCalledTimes(3)
    expect(bus.listenerCount('lockout')).toBe(1)
  })

  it('runs the handlers of both kinds registered when the emit began, and no later one', async () => {
    const bus = make()
    const late = vi.fn()
    bus.on('lockout', () => void bus.on('lockout', late), ORIGIN)
    bus.on('lockout', () => void bus.on('lockout', late, ORIGIN))

    await bus.emit('lockout', LOCKOUT)
    expect(late).not.toHaveBeenCalled()

    await bus.emit('lockout', LOCKOUT)
    expect(late).toHaveBeenCalledTimes(2)
  })

  it('keeps running the rest when a handler of either kind throws', async () => {
    const bus = make()
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const after = vi.fn()
    bus.on(
      'lockout',
      () => {
        throw new Error('origin')
      },
      ORIGIN,
    )
    bus.on('lockout', () => {
      throw new Error('fleet')
    })
    bus.on('lockout', after)

    await expect(bus.emit('lockout', LOCKOUT)).resolves.toBeUndefined()
    expect(after).toHaveBeenCalledOnce()
    expect(stderr).toHaveBeenCalledTimes(2)
    stderr.mockRestore()
  })
})

describe('InMemoryEvents delivery', () => {
  it('runs both kinds on every emit, since every handler is on this server', async () => {
    const bus = new InMemoryEvents()
    const origin = vi.fn()
    const fleet = vi.fn()
    bus.on('lockout', origin, ORIGIN)
    bus.on('lockout', fleet)

    await bus.emit('lockout', LOCKOUT)

    expect(origin).toHaveBeenCalledWith(LOCKOUT)
    expect(fleet).toHaveBeenCalledWith(LOCKOUT)
  })

  it('lists the events holding a fleet handler, and only those', () => {
    const bus = new InMemoryEvents()
    expect(bus.fleetEvents()).toEqual([])

    bus.on('lockout', vi.fn(), ORIGIN)
    bus.on('authz.revoked', vi.fn())
    bus.on('session.created', vi.fn(), { delivery: 'fleet' })
    const off = bus.on('signup.completed', vi.fn(), {})
    expect(bus.fleetEvents()).toEqual(['authz.revoked', 'session.created', 'signup.completed'])

    off()
    expect(bus.fleetEvents()).toEqual(['authz.revoked', 'session.created'])
  })

  it('counts a delivery it does not know as fleet', () => {
    const bus = new InMemoryEvents()
    const opts: Events.OnOptions = {}
    Object.assign(opts, { delivery: 'orgin' })
    bus.on('lockout', vi.fn(), opts)
    expect(bus.fleetEvents()).toEqual(['lockout'])
  })
})

describe('the wrappers pass the delivery through', () => {
  it('withAuditStamping forwards the options and the fleet list', () => {
    const bus = new InMemoryEvents()
    const stamped = withAuditStamping(bus)
    stamped.on('lockout', vi.fn(), ORIGIN)
    expect(bus.fleetEvents()).toEqual([])
    expect(stamped.fleetEvents?.()).toEqual([])

    stamped.on('authz.revoked', vi.fn())
    expect(stamped.fleetEvents?.()).toEqual(['authz.revoked'])
  })

  it('leaves fleetEvents off a wrapped bus that has none', () => {
    const bus = new InMemoryEvents()
    const stamped = withAuditStamping({ emit: (e, p) => bus.emit(e, p), on: (e, h, o) => bus.on(e, h, o) })
    expect(stamped.fleetEvents).toBeUndefined()
  })

  it('engine.events reaches the configured bus', () => {
    const bus = new InMemoryEvents()
    const engine = createTest<P>({ events: bus })
    engine.events.on('lockout', vi.fn(), ORIGIN)
    expect(bus.listenerCount('lockout')).toBe(1)
    expect(bus.fleetEvents()).toEqual([])

    engine.events.on('authz.revoked', vi.fn())
    expect(bus.fleetEvents()).toEqual(['authz.revoked'])
  })

  it('engine.events reports the fallback bus when none is configured', () => {
    const engine = createTest<P>()
    engine.events.on('lockout', vi.fn(), ORIGIN)
    expect(engine.events.fleetEvents?.()).toEqual([])

    engine.events.on('lockout', vi.fn())
    expect(engine.events.fleetEvents?.()).toEqual(['lockout'])
  })

  it("a bound engine's bus reaches the configured bus", () => {
    const bus = new InMemoryEvents()
    const engine = createTest<P>({ events: bus, stores: joinable() })
    const probe = new BusProbe()
    engine.providers.register(probe)
    engine.withTransaction({})
    const [bound] = probe.seen
    if (!bound) throw new Error('the probe never saw the bound bus')

    bound.on('lockout', vi.fn(), ORIGIN)
    expect(bus.listenerCount('lockout')).toBe(1)
    expect(bus.fleetEvents()).toEqual([])

    bound.on('authz.revoked', vi.fn())
    expect(bus.fleetEvents()).toEqual(['authz.revoked'])
  })

  it('runs an audit-style handler once across two engines, through engine.events and a transaction', async () => {
    const redis = new SocketRedis()
    const adapter = new MemoryAdapter<P>()
    const a = createTest<P>({ events: server(redis), stores: joinable(adapter) })
    const b = createTest<P>({ events: server(redis), stores: joinable(adapter) })
    const audit = { a: vi.fn(), b: vi.fn() }
    const cache = { a: vi.fn(), b: vi.fn() }
    a.events.on('signup.completed', audit.a, ORIGIN)
    b.events.on('signup.completed', audit.b, ORIGIN)
    a.events.on('signup.completed', cache.a)
    b.events.on('signup.completed', cache.b)
    await settle()

    await a.identities.create({ profile: { email: 'a@x', username: 'a' } })
    await settle()
    expect(audit.a).toHaveBeenCalledOnce()
    expect(audit.b).not.toHaveBeenCalled()
    expect(cache.a).toHaveBeenCalledOnce()
    expect(cache.b).toHaveBeenCalledOnce()

    const tx = b.withTransaction({})
    await tx.identities.create({ profile: { email: 'b@x', username: 'b' } })
    expect(audit.b).not.toHaveBeenCalled()
    await tx.pending.flush()
    await settle()
    expect(audit.a).toHaveBeenCalledOnce()
    expect(audit.b).toHaveBeenCalledOnce()
    expect(cache.a).toHaveBeenCalledTimes(2)
    expect(cache.b).toHaveBeenCalledTimes(2)
  })
})

describe('Events.OnOptions', () => {
  it('takes origin or fleet and nothing else', () => {
    const bus: Events.IBus = withAuditStamping(new InMemoryEvents())
    bus.on('lockout', () => {}, { delivery: 'origin' })
    bus.on('lockout', () => {}, { delivery: 'fleet' })
    bus.on('lockout', () => {}, {})
    // @ts-expect-error not a delivery
    bus.on('lockout', () => {}, { delivery: 'nope' })
    // @ts-expect-error not an option
    bus.on('lockout', () => {}, { deliver: 'origin' })
    expectTypeOf<Events.Delivery>().toEqualTypeOf<'origin' | 'fleet'>()
  })
})
