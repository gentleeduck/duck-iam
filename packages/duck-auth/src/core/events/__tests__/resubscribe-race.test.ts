/** The channel must still be subscribed after a handler swap. `RedisEvents.on()` promises the valkey
 *  adapter "at most one live subscription per channel", and the adapter's unsubscribe is channel-global. */
import { describe, expect, it, vi } from 'vitest'
import type { ValkeySubscriberClient } from '~/core/drivers/valkey-like'
import { SUBSCRIBE_RETRY_MS } from '~/core/events/events.constants'
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

  it('hears a channel only through the listener that subscribed to it', async () => {
    const { bus, sub } = wire()
    const seen: string[] = []
    bus.on('lockout', () => {
      seen.push('lockout')
    })
    bus.on('session.revoked', () => {
      seen.push('session.revoked')
    })
    await settle()

    sub.deliver(CHANNEL, fromPeer())
    await settle()
    expect(seen).toEqual(['lockout'])
  })

  it('a failed subscribe leaves no listener behind, so the retry hears each message once', async () => {
    const sub = new FakeSubscriber()
    const original = sub.subscribe.bind(sub)
    sub.subscribe = async () => {
      sub.subscribe = original
      throw new Error('connection refused')
    }
    const bus = valkeyEvents({ cmd: new FakeValkey(), prefix: 'test', sub })
    const seen: string[] = []
    bus.on('lockout', () => {
      seen.push('first')
    })
    await settle()
    bus.on('lockout', () => {
      seen.push('second')
    })
    await settle()

    sub.deliver(CHANNEL, fromPeer())
    await settle()
    expect(seen).toEqual(['first', 'second'])
  })

  it('logs an unsubscribe that failed, and the next on() still hears the fleet', async () => {
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason)
    }
    process.on('unhandledRejection', onUnhandled)
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { bus, sub } = wire()
      sub.unsubscribe = async () => {
        throw new Error('Connection is closed.')
      }
      const unsub = bus.on('lockout', () => {})
      await settle()
      unsub()
      await settle()
      expect(unhandled).toEqual([])
      expect(logged.mock.calls.map(([line]) => line)).toEqual([
        '[@gentleduck/auth] RedisEvents could not unsubscribe from "lockout":',
      ])

      const seen: unknown[] = []
      bus.on('lockout', () => {
        seen.push(1)
      })
      await settle()
      sub.deliver(CHANNEL, fromPeer())
      await settle()
      expect(seen).toHaveLength(1)
    } finally {
      process.off('unhandledRejection', onUnhandled)
      logged.mockRestore()
    }
  })
})

describe('RedisEvents on valkey: origin handlers hold no channel', () => {
  it('never subscribes for origin handlers, and closes the channel with the last fleet one', async () => {
    const { bus, sub } = wire()
    bus.on('lockout', () => {}, { delivery: 'origin' })
    await settle()
    expect(sub.subscribeCalls).toBe(0)

    const off = bus.on('lockout', () => {})
    await settle()
    expect(sub.channels.has(CHANNEL)).toBe(true)

    off()
    await settle()
    expect(sub.channels.has(CHANNEL)).toBe(false)
  })

  it('runs the fleet handlers, never the origin ones, for a message from a peer', async () => {
    const { bus, sub } = wire()
    const origin = vi.fn()
    const fleet = vi.fn()
    bus.on('lockout', origin, { delivery: 'origin' })
    bus.on('lockout', fleet)
    await settle()

    sub.deliver(CHANNEL, fromPeer())
    await settle()

    expect(fleet).toHaveBeenCalledOnce()
    expect(origin).not.toHaveBeenCalled()
  })
})

describe('RedisEvents: a subscribe that failed is retried until it lands', () => {
  /** A subscriber that refuses its first `failures` subscribes, as while Redis is unreachable. */
  function refusing(failures: number): { bus: ReturnType<typeof valkeyEvents>; sub: FakeSubscriber } {
    const sub = new FakeSubscriber()
    const original = sub.subscribe.bind(sub)
    let left = failures
    sub.subscribe = async (...channels: string[]) => {
      if (left-- <= 0) return original(...channels)
      sub.subscribeCalls++
      throw new Error('connect ECONNREFUSED')
    }
    return { bus: valkeyEvents({ cmd: new FakeValkey(), prefix: 'test', sub }), sub }
  }

  it('hears the fleet once Redis answers, with no later on() to prompt it, and logs the failure', async () => {
    vi.useFakeTimers()
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { bus, sub } = refusing(1)
      const seen: unknown[] = []
      bus.on('lockout', () => {
        seen.push(1)
      })
      await vi.advanceTimersByTimeAsync(0)
      expect(sub.channels.has(CHANNEL)).toBe(false)
      expect(logged.mock.calls.map(([line]) => line)).toEqual([
        '[@gentleduck/auth] RedisEvents could not subscribe to "lockout", retrying:',
      ])

      await vi.advanceTimersByTimeAsync(SUBSCRIBE_RETRY_MS)
      sub.deliver(CHANNEL, fromPeer())
      await vi.advanceTimersByTimeAsync(0)
      expect(seen).toHaveLength(1)
      expect(logged).toHaveBeenCalledOnce()
    } finally {
      logged.mockRestore()
      vi.useRealTimers()
    }
  })

  it('subscribes once, logs nothing and holds no timer when Redis answers the first time', async () => {
    vi.useFakeTimers()
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { bus, sub } = refusing(0)
      bus.on('lockout', () => {})
      await vi.advanceTimersByTimeAsync(0)
      expect(sub.subscribeCalls).toBe(1)
      expect(sub.channels.has(CHANNEL)).toBe(true)
      expect(vi.getTimerCount()).toBe(0)
      expect(logged).not.toHaveBeenCalled()
    } finally {
      logged.mockRestore()
      vi.useRealTimers()
    }
  })
  it('backs off, doubling from a second to at most thirty', async () => {
    vi.useFakeTimers()
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { bus, sub } = refusing(Number.POSITIVE_INFINITY)
      bus.on('lockout', () => {})
      let now = 0
      const callsAt = async (ms: number): Promise<number> => {
        await vi.advanceTimersByTimeAsync(ms - now)
        now = ms
        return sub.subscribeCalls
      }
      expect(await callsAt(0)).toBe(1)
      expect(await callsAt(999)).toBe(1)
      expect(await callsAt(1_000)).toBe(2)
      expect(await callsAt(3_000)).toBe(3)
      expect(await callsAt(7_000)).toBe(4)
      expect(await callsAt(15_000)).toBe(5)
      expect(await callsAt(31_000)).toBe(6)
      expect(await callsAt(60_999)).toBe(6)
      expect(await callsAt(61_000)).toBe(7)
      expect(await callsAt(91_000)).toBe(8)
      expect(logged).toHaveBeenCalledTimes(8)
    } finally {
      logged.mockRestore()
      vi.useRealTimers()
    }
  })

  it('stops once the event has no fleet handler, leaving no timer to hold the process', async () => {
    vi.useFakeTimers()
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { bus, sub } = refusing(Number.POSITIVE_INFINITY)
      bus.on('lockout', () => {}, { delivery: 'origin' })
      const off = bus.on('lockout', () => {})
      await vi.advanceTimersByTimeAsync(0)
      expect(sub.subscribeCalls).toBe(1)

      off()
      await vi.advanceTimersByTimeAsync(0)
      expect(vi.getTimerCount()).toBe(0)
      await vi.advanceTimersByTimeAsync(120_000)
      expect(sub.subscribeCalls).toBe(1)
    } finally {
      logged.mockRestore()
      vi.useRealTimers()
    }
  })

  it('keeps retrying while another fleet handler remains', async () => {
    vi.useFakeTimers()
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { bus, sub } = refusing(1)
      const seen: unknown[] = []
      const off = bus.on('lockout', () => {})
      bus.on('lockout', () => {
        seen.push(1)
      })
      await vi.advanceTimersByTimeAsync(0)
      off()
      await vi.advanceTimersByTimeAsync(SUBSCRIBE_RETRY_MS)
      expect(sub.subscribeCalls).toBe(2)

      sub.deliver(CHANNEL, fromPeer())
      await vi.advanceTimersByTimeAsync(0)
      expect(seen).toHaveLength(1)
    } finally {
      logged.mockRestore()
      vi.useRealTimers()
    }
  })
})
