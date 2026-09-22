/** The channel must still be subscribed after a handler swap. `RedisEvents.on()` promises the valkey
 *  adapter "at most one live subscription per channel", and the adapter's unsubscribe is channel-global. */
import { describe, expect, it } from 'vitest'
import type { ValkeySubscriberClient } from '~/core/drivers/valkey-like'
import { valkeyEvents } from '~/core/events/events.valkey'
import { FakeValkey } from '~/test/fake-valkey'

/** ioredis' semantics: `UNSUBSCRIBE channel` cancels the channel for the whole connection, whatever
 *  `'message'` listeners are still attached, and the server then delivers nothing for it. */
class FakeSubscriber implements ValkeySubscriberClient.Me {
  readonly channels = new Set<string>()
  subscribeCalls = 0
  unsubscribeCalls = 0
  private readonly _listeners = new Set<(channel: string, message: string) => void>()

  async subscribe(...channels: string[]): Promise<unknown> {
    this.subscribeCalls++
    for (const channel of channels) this.channels.add(channel)
    return channels.length
  }

  async unsubscribe(...channels: string[]): Promise<unknown> {
    this.unsubscribeCalls++
    for (const channel of channels) this.channels.delete(channel)
    return channels.length
  }

  on(_event: 'message', listener: (channel: string, message: string) => void): unknown {
    this._listeners.add(listener)
    return this
  }

  off(_event: 'message', listener: (channel: string, message: string) => void): unknown {
    this._listeners.delete(listener)
    return this
  }

  /** What a peer node publishing to `channel` actually delivers here. */
  deliver(channel: string, message: string): void {
    if (!this.channels.has(channel)) return
    for (const listener of [...this._listeners]) listener(channel, message)
  }
}

/** Drain the microtask queue plus a macrotask, so an in-flight teardown has landed. */
async function settle(): Promise<void> {
  for (let i = 0; i < 4; i++) await new Promise((resolve) => setTimeout(resolve, 0))
}

const CHANNEL = 'test:lockout'

function fromPeer(): string {
  return JSON.stringify({ from: 'another-node', payload: { identityId: 'ident-1', until: Date.now() + 60_000 } })
}

function wire(): { bus: ReturnType<typeof valkeyEvents>; sub: FakeSubscriber } {
  const sub = new FakeSubscriber()
  return { bus: valkeyEvents({ cmd: new FakeValkey(), prefix: 'test', sub }), sub }
}

describe('RedisEvents: swapping the last handler must not leave the channel closed', () => {
  it('a handler registered right after the previous one unsubscribed still receives fleet events', async () => {
    const { bus, sub } = wire()
    const unsub = bus.on('lockout', () => {})
    await settle()

    unsub()
    const seen: unknown[] = []
    bus.on('lockout', () => {
      seen.push(1)
    })
    await settle()

    sub.deliver(CHANNEL, fromPeer())
    await settle()
    expect(seen).toHaveLength(1)
  })

  it('leaves the channel subscribed at the server after the swap', async () => {
    const { bus, sub } = wire()
    const unsub = bus.on('lockout', () => {})
    await settle()
    unsub()
    bus.on('lockout', () => {})
    await settle()

    expect(sub.channels.has(CHANNEL)).toBe(true)
  })

  it('reports a listener for the event it can no longer hear, which is what makes it silent', async () => {
    const { bus, sub } = wire()
    const unsub = bus.on('lockout', () => {})
    await settle()
    unsub()
    bus.on('lockout', () => {})
    await settle()

    // `strict()` gates on this count, so the fleet gap never reaches a boot-time check.
    expect(bus.listenerCount('lockout')).toBe(1)
    expect(sub.channels.has(CHANNEL)).toBe(true)
  })

  it('a local emit still reaches the new handler, so only the cross-node half goes missing', async () => {
    const { bus } = wire()
    const unsub = bus.on('lockout', () => {})
    await settle()
    unsub()
    const seen: unknown[] = []
    bus.on('lockout', () => {
      seen.push(1)
    })
    await settle()

    await bus.emit('lockout', { identityId: 'ident-1', until: Date.now() + 60_000 })
    expect(seen).toHaveLength(1)
  })

  it('reopens the channel rather than reusing a cancelled subscription', async () => {
    const { bus, sub } = wire()
    const unsub = bus.on('lockout', () => {})
    await settle()
    unsub()
    bus.on('lockout', () => {})
    await settle()

    expect(sub.unsubscribeCalls).toBe(1)
    expect(sub.subscribeCalls).toBe(2)
  })

  it('still tears the channel down when the handlers really do drain to zero', async () => {
    const { bus, sub } = wire()
    const unsub = bus.on('lockout', () => {})
    await settle()
    unsub()
    await settle()

    expect(sub.channels.has(CHANNEL)).toBe(false)
    expect(sub.unsubscribeCalls).toBe(1)
  })

  it('does not tear the channel down while another handler is still on it', async () => {
    const { bus, sub } = wire()
    const unsub = bus.on('lockout', () => {})
    bus.on('lockout', () => {})
    await settle()
    unsub()
    await settle()

    expect(sub.channels.has(CHANNEL)).toBe(true)
    expect(sub.unsubscribeCalls).toBe(0)
  })

  it('a failed subscribe is still retried by the next on()', async () => {
    const sub = new FakeSubscriber()
    let first = true
    const original = sub.subscribe.bind(sub)
    sub.subscribe = async (...channels: string[]) => {
      if (first) {
        first = false
        throw new Error('connection refused')
      }
      return original(...channels)
    }
    const bus = valkeyEvents({ cmd: new FakeValkey(), prefix: 'test', sub })

    bus.on('lockout', () => {})
    await settle()
    expect(sub.channels.has(CHANNEL)).toBe(false)

    bus.on('lockout', () => {})
    await settle()
    expect(sub.channels.has(CHANNEL)).toBe(true)
  })
})
