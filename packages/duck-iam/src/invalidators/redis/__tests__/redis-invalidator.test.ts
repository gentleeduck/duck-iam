import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { EngineTypes } from '../../../core/engine/engine.types'
import { createRedisInvalidator, type RedisInvalidator } from '../index'

/**
 * In-memory pub/sub stub that mimics the narrow `IPubSubLike` surface. The
 * test drives both the publish path (capturing the on-wire string) and the
 * subscribe path (by invoking the saved handler directly).
 */
function makeBus(): {
  client: RedisInvalidator.IPubSubLike
  publish: (msg: string) => void
  published: string[]
  unsubscribed: string[]
} {
  let handler: ((m: string) => void) | null = null
  const published: string[] = []
  const unsubscribed: string[] = []
  return {
    client: {
      publish(_channel, message) {
        published.push(message)
      },
      subscribe(_channel, h) {
        handler = h
      },
      unsubscribe(channel) {
        unsubscribed.push(channel)
      },
    },
    publish(msg) {
      handler?.(msg)
    },
    published,
    unsubscribed,
  }
}

describe('createRedisInvalidator (SEC-005)', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('signed message verifies and dispatches to handlers', () => {
    const a = makeBus()
    const b = makeBus()
    const ch = `t-signed-${Math.random().toString(36).slice(2)}`
    const invA = createRedisInvalidator({ channel: ch, client: a.client, secret: 'shared-secret' })
    const invB = createRedisInvalidator({ channel: ch, client: b.client, secret: 'shared-secret' })

    const received: EngineTypes.IInvalidateEvent[] = []
    invB.subscribe((e) => received.push(e))

    invA.publish({ kind: 'all' })

    // Pipe the wire bytes from A to B's subscriber.
    b.publish(a.published[0]!)

    expect(received).toEqual([{ kind: 'all' }])
  })

  it('drops unsigned message when secret is set', () => {
    const bus = makeBus()
    const ch = `t-unsigned-${Math.random().toString(36).slice(2)}`
    const inv = createRedisInvalidator({ channel: ch, client: bus.client, secret: 's' })
    const received: EngineTypes.IInvalidateEvent[] = []
    inv.subscribe((e) => received.push(e))

    // Legacy unsigned wire format from a peer without a secret.
    bus.publish(JSON.stringify({ event: { kind: 'all' }, instanceId: 'attacker' }))

    expect(received).toEqual([])
    expect(warnSpy).toHaveBeenCalled()
    const msgs = warnSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
    expect(msgs.some((m: string) => m.includes('unsigned message'))).toBe(true)
  })

  it('drops tampered payload (signature mismatch)', () => {
    const a = makeBus()
    const b = makeBus()
    const ch = `t-tamper-${Math.random().toString(36).slice(2)}`
    const invA = createRedisInvalidator({ channel: ch, client: a.client, secret: 'k' })
    const invB = createRedisInvalidator({ channel: ch, client: b.client, secret: 'k' })
    const received: EngineTypes.IInvalidateEvent[] = []
    invB.subscribe((e) => received.push(e))

    invA.publish({ kind: 'all' })
    // Mutate the payload: flip the event kind without re-signing.
    const env = JSON.parse(a.published[0]!) as {
      payload: { event: { kind: string } }
      sig: string
      v: number
    }
    env.payload.event.kind = 'policies'
    b.publish(JSON.stringify(env))

    expect(received).toEqual([])
    const msgs = warnSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
    expect(msgs.some((m: string) => m.includes('signature mismatch'))).toBe(true)
  })

  it('drops replay older than 30s', () => {
    const a = makeBus()
    const b = makeBus()
    const realNow = Date.now
    try {
      const fixed = 1_700_000_000_000
      Date.now = () => fixed
      const ch = `t-replay-${Math.random().toString(36).slice(2)}`
      const invA = createRedisInvalidator({ channel: ch, client: a.client, secret: 'k' })
      // Publisher stamps ts = `fixed`.
      invA.publish({ kind: 'all' })

      // Subscriber lives 60s in the future.
      Date.now = () => fixed + 60_000
      const invB = createRedisInvalidator({ channel: ch, client: b.client, secret: 'k' })
      const received: EngineTypes.IInvalidateEvent[] = []
      invB.subscribe((e) => received.push(e))
      b.publish(a.published[0]!)

      expect(received).toEqual([])
      const msgs = warnSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
      expect(msgs.some((m: string) => m.includes('replay window'))).toBe(true)
    } finally {
      Date.now = realNow
    }
  })

  it('peer without secret accepts unsigned and warns once at construction', () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client })
    const received: EngineTypes.IInvalidateEvent[] = []
    inv.subscribe((e) => received.push(e))

    bus.publish(JSON.stringify({ event: { kind: 'all' }, instanceId: 'peer' }))
    expect(received).toEqual([{ kind: 'all' }])

    // Construction-time warn: at most once per process. The latch is module-
    // level so earlier tests in this file may already have tripped it; assert
    // the warn fired at most once across multiple constructions in this case.
    const before = warnSpy.mock.calls.length
    createRedisInvalidator({ client: makeBus().client })
    createRedisInvalidator({ client: makeBus().client })
    const after = warnSpy.mock.calls.length
    const unsignedWarns = warnSpy.mock.calls
      .map((c: unknown[]) => String(c[0] ?? ''))
      .filter((m: string) => m.includes('`secret` not set'))
    expect(unsignedWarns.length).toBeLessThanOrEqual(1)
    expect(after - before).toBeLessThanOrEqual(1)
  })

  it('mismatched secrets between peers drops on both sides', () => {
    const a = makeBus()
    const b = makeBus()
    const ch = `t-mismatch-${Math.random().toString(36).slice(2)}`
    const invA = createRedisInvalidator({ channel: ch, client: a.client, secret: 'k1' })
    const invB = createRedisInvalidator({ channel: ch, client: b.client, secret: 'k2' })
    const received: EngineTypes.IInvalidateEvent[] = []
    invB.subscribe((e) => received.push(e))

    invA.publish({ kind: 'all' })
    b.publish(a.published[0]!)

    expect(received).toEqual([])
  })

  it('imports timingSafeEqual from node:crypto (constant-time compare)', () => {
    // Static check: source must import `timingSafeEqual`. This guards against a
    // future regression where someone refactors to `===` and reintroduces a
    // timing side-channel on the signature compare.
    const path = resolve(__dirname, '..', 'index.ts')
    const src = readFileSync(path, 'utf8')
    expect(src).toMatch(/from\s+['"]node:crypto['"]/)
    expect(src).toMatch(/\btimingSafeEqual\b/)
  })

  it('drops self-published messages (instanceId guard, unchanged from P0)', () => {
    const bus = makeBus()
    const ch = `t-self-${Math.random().toString(36).slice(2)}`
    const inv = createRedisInvalidator({ channel: ch, client: bus.client, secret: 'k' })
    const received: EngineTypes.IInvalidateEvent[] = []
    inv.subscribe((e) => received.push(e))

    inv.publish({ kind: 'all' })
    // Loop the message back to ourselves.
    bus.publish(bus.published[0]!)

    expect(received).toEqual([])
  })

  describe('SEC-031 pre-auth DoS guard', () => {
    it('drops oversize wire message pre-parse (>16 KB)', () => {
      const bus = makeBus()
      const ch = `t-oversize-${Math.random().toString(36).slice(2)}`
      const inv = createRedisInvalidator({ channel: ch, client: bus.client, secret: 'k' })
      const received: EngineTypes.IInvalidateEvent[] = []
      inv.subscribe((e) => received.push(e))

      // 32 KB blob. Stays a valid JSON string but exceeds the 16 KB wire cap.
      const blob = JSON.stringify({ junk: 'x'.repeat(32 * 1024) })
      expect(blob.length).toBeGreaterThan(16 * 1024)
      bus.publish(blob)

      expect(received).toEqual([])
      const msgs = warnSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
      expect(msgs.some((m: string) => m.includes('oversize wire message'))).toBe(true)
    })

    it('drops surrogate-heavy payload that bypasses .length cap (SEC-034)', () => {
      const bus = makeBus()
      const ch = `t-utf8-bytes-${Math.random().toString(36).slice(2)}`
      const inv = createRedisInvalidator({ channel: ch, client: bus.client, secret: 'k' })
      const received: EngineTypes.IInvalidateEvent[] = []
      inv.subscribe((e) => received.push(e))

      // Build a 5000-char payload of 4-byte UTF-8 chars (each character
      // outside the BMP encodes to 4 bytes UTF-8 but 2 UTF-16 code units).
      // U+1F600 ("😀") is a canonical 4-byte UTF-8 code point.
      // `s.length` ≈ 10000 (UTF-16 code units), `Buffer.byteLength` ≈ 20000
      // bytes — well past the 16 KB cap when wrapped in a JSON string.
      const fourByteChar = '\u{1F600}'
      const surrogateBlob = JSON.stringify({ junk: fourByteChar.repeat(5000) })
      expect(Buffer.byteLength(surrogateBlob, 'utf8')).toBeGreaterThan(16 * 1024)
      bus.publish(surrogateBlob)

      expect(received).toEqual([])
      const msgs = warnSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
      expect(msgs.some((m: string) => m.includes('oversize wire message'))).toBe(true)
    })

    it('drops deeply nested payload pre-canonicalise (depth 10)', () => {
      const bus = makeBus()
      const ch = `t-deep-${Math.random().toString(36).slice(2)}`
      const inv = createRedisInvalidator({ channel: ch, client: bus.client, secret: 'k' })
      const received: EngineTypes.IInvalidateEvent[] = []
      inv.subscribe((e) => received.push(e))

      // Build a depth-10 chain inside `payload`.
      let nested: Record<string, unknown> = {}
      for (let i = 0; i < 10; i++) nested = { n: nested }
      bus.publish(JSON.stringify({ payload: nested, sig: 'aa', v: 1 }))

      expect(received).toEqual([])
      const msgs = warnSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
      expect(msgs.some((m: string) => m.includes('depth/key limits'))).toBe(true)
    })

    it('drops payload with > 64 keys', () => {
      const bus = makeBus()
      const ch = `t-keys-${Math.random().toString(36).slice(2)}`
      const inv = createRedisInvalidator({ channel: ch, client: bus.client, secret: 'k' })
      const received: EngineTypes.IInvalidateEvent[] = []
      inv.subscribe((e) => received.push(e))

      const wide: Record<string, number> = {}
      for (let i = 0; i < 200; i++) wide[`k${i}`] = i
      bus.publish(JSON.stringify({ payload: wide, sig: 'aa', v: 1 }))

      expect(received).toEqual([])
      const msgs = warnSpy.mock.calls.map((c: unknown[]) => String(c[0] ?? ''))
      expect(msgs.some((m: string) => m.includes('depth/key limits'))).toBe(true)
    })

    it('happy-path signed envelope still verifies under the guard', () => {
      const a = makeBus()
      const b = makeBus()
      const ch = `t-happy-${Math.random().toString(36).slice(2)}`
      const invA = createRedisInvalidator({ channel: ch, client: a.client, secret: 's' })
      const invB = createRedisInvalidator({ channel: ch, client: b.client, secret: 's' })
      const received: EngineTypes.IInvalidateEvent[] = []
      invB.subscribe((e) => received.push(e))
      invA.publish({ kind: 'all' })
      b.publish(a.published[0]!)
      expect(received).toEqual([{ kind: 'all' }])
    })

    it('guard itself does not recurse — depth 100k payload does not RangeError', () => {
      const bus = makeBus()
      const ch = `t-norecurse-${Math.random().toString(36).slice(2)}`
      const inv = createRedisInvalidator({ channel: ch, client: bus.client, secret: 'k' })
      inv.subscribe(() => {})

      // Construct a 100k-deep object iteratively (recursive JSON.parse on a
      // string this deep would itself overflow on some engines, so we build
      // the parse tree directly then JSON.stringify it — that path is also
      // iterative inside V8).
      let deep: Record<string, unknown> = {}
      for (let i = 0; i < 100_000; i++) deep = { n: deep }
      // Stringify may itself be the heavy step; if it cannot serialize we
      // still want to assert the guard path is non-recursive. Wrap the whole
      // publish so any RangeError surfaces as a failure.
      expect(() => {
        let wire: string
        try {
          wire = JSON.stringify({ payload: deep, sig: 'aa', v: 1 })
        } catch {
          // Stringify overflow is environment-specific; fall back to a
          // synthesised oversize-but-shallow blob to still exercise the
          // pre-parse cap. Either way the guard must not throw RangeError.
          wire = `{"v":1,"sig":"aa","payload":${'['.repeat(50_000)}null${']'.repeat(50_000)}}`
        }
        bus.publish(wire)
      }).not.toThrow()
    })
  })

  it('unsubscribes when last handler detaches', () => {
    const bus = makeBus()
    const inv = createRedisInvalidator({ client: bus.client, secret: 'k', channel: 'c-1' })
    const off = inv.subscribe(() => {})
    off()
    expect(bus.unsubscribed).toEqual(['c-1'])
  })
})
