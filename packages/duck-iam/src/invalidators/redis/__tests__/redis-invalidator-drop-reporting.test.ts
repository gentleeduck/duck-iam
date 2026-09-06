import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

/**
 * Two failures that shared one symptom: a dropped invalidation nobody could
 * see.
 *
 * The first is a `secret` rolled out to some nodes and not others. Each side
 * refuses the other's envelopes - `'v:1 envelope received without secret
 * configured'` one way, `'unsigned message with secret configured'` the other -
 * so no invalidation crosses in either direction for the whole rollout. Caches
 * never converge and the failure is stale **allow**: a revoked role keeps
 * working on every node until its own TTL retires it. Nothing threw, no request
 * errored, and the only report was a `console.warn` coalesced to one line per
 * minute. `onMessageDropped` is the channel that was missing.
 *
 * The second is the coalescing budget itself. `_DROP_WARN_STATE` is
 * module-level and was keyed on the channel alone, so inbound drops and publish
 * failures shared one 60s window - and inbound is the half an attacker
 * controls. One junk message a minute claimed the window and suppressed the
 * publish-failure warning for a broker outage running at the same time.
 */
type Handler = (message: string) => void

/** A bus that lets a test deliver a message as if a peer had published it. */
function makeBus(): IamRedisInvalidator.IPubSubLike & { deliver: Handler; publishes: string[] } {
  let handler: Handler | null = null
  const publishes: string[] = []
  return {
    deliver(message) {
      if (!handler) throw new Error('nothing subscribed')
      handler(message)
    },
    publish(_channel: string, payload: string) {
      publishes.push(payload)
    },
    publishes,
    subscribe(_channel: string, cb: Handler) {
      handler = cb
    },
    unsubscribe() {},
  }
}

/** A bus whose `publish` always fails, and which can still deliver inbound. */
function makeFailingBus(): IamRedisInvalidator.IPubSubLike & { deliver: Handler } {
  let handler: Handler | null = null
  return {
    deliver(message) {
      if (!handler) throw new Error('nothing subscribed')
      handler(message)
    },
    publish() {
      throw new Error('connection lost')
    },
    subscribe(_channel: string, cb: Handler) {
      handler = cb
    },
    unsubscribe() {},
  }
}

/** Module-level latch state is keyed by channel, so every test needs its own. */
function uniqueChannel(): string {
  return `t-drop-${Math.random().toString(36).slice(2)}`
}

describe('an inbound drop is reported to the operator, not only to the log', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('a signed peer talking to an unsigned node reports the mismatch', () => {
    // The node has no secret; the peer signs. Every one of the peer's
    // invalidations is refused, which is the rollout half that keeps serving
    // stale allow.
    const channel = uniqueChannel()
    const bus = makeBus()
    const seen: { reason: string; channel: string }[] = []
    const inv = createIamRedisInvalidator({
      channel,
      client: bus,
      onMessageDropped: (reason, ch) => seen.push({ channel: ch, reason }),
    })
    inv.subscribe(() => {})

    bus.deliver(
      JSON.stringify({
        payload: { event: { kind: 'all' }, instanceId: 'peer', ts: Date.now() },
        sig: 'ab'.repeat(32),
        v: 1,
      }),
    )

    expect(seen).toEqual([{ channel, reason: 'v:1 envelope received without secret configured' }])
  })

  it('an unsigned peer talking to a signed node reports the mismatch', () => {
    // The other half of the same rollout, and a different code path.
    const channel = uniqueChannel()
    const bus = makeBus()
    const seen: string[] = []
    const inv = createIamRedisInvalidator({
      channel,
      client: bus,
      onMessageDropped: (reason) => seen.push(reason),
      secret: 'shared-secret',
    })
    inv.subscribe(() => {})

    bus.deliver(JSON.stringify({ event: { kind: 'all' }, instanceId: 'peer' }))

    expect(seen).toEqual(['unsigned message with secret configured'])
  })

  it('the handler is never called for a dropped message', () => {
    // The reporting is the point, but so is the refusal: a mismatch must not
    // become "apply it anyway".
    const channel = uniqueChannel()
    const bus = makeBus()
    const applied: unknown[] = []
    const inv = createIamRedisInvalidator({ channel, client: bus, onMessageDropped: () => {}, secret: 's' })
    inv.subscribe((e) => applied.push(e))

    bus.deliver(JSON.stringify({ event: { kind: 'all' }, instanceId: 'peer' }))

    expect(applied).toEqual([])
  })

  it('the hook replaces the console warning rather than doubling it', () => {
    const channel = uniqueChannel()
    const bus = makeBus()
    const inv = createIamRedisInvalidator({ channel, client: bus, onMessageDropped: () => {}, secret: 's' })
    inv.subscribe(() => {})

    bus.deliver(JSON.stringify({ event: { kind: 'all' }, instanceId: 'peer' }))

    expect(warnSpy.mock.calls.filter((c: unknown[]) => /dropping unverifiable/.test(String(c[0])))).toEqual([])
  })

  it('a throwing hook does not escape into the message handler', () => {
    // Fail-soft, as with onPublishError and onSubscribeError. A pub/sub
    // callback that throws takes the client's listener down with it.
    const channel = uniqueChannel()
    const bus = makeBus()
    const inv = createIamRedisInvalidator({
      channel,
      client: bus,
      onMessageDropped: () => {
        throw new Error('operator hook blew up')
      },
      secret: 's',
    })
    inv.subscribe(() => {})

    expect(() => bus.deliver(JSON.stringify({ event: { kind: 'all' }, instanceId: 'peer' }))).not.toThrow()
  })

  it('a matching secret still applies the peer event - the control', () => {
    // Without this every assertion above is satisfied by an invalidator that
    // drops everything.
    const channel = uniqueChannel()
    const bus = makeBus()
    const applied: unknown[] = []
    const dropped: string[] = []
    const peer = createIamRedisInvalidator({ channel, client: bus, secret: 'shared-secret' })
    const inv = createIamRedisInvalidator({
      channel,
      client: bus,
      onMessageDropped: (r) => dropped.push(r),
      secret: 'shared-secret',
    })
    inv.subscribe((e) => applied.push(e))

    peer.publish({ kind: 'all' })
    const wire = bus.publishes[0]
    expect(wire).toBeDefined()
    bus.deliver(wire as string)

    expect(dropped).toEqual([])
    expect(applied).toEqual([{ kind: 'all' }])
  })
})

describe('inbound drops and publish failures do not share a coalescing budget', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('a junk inbound message does not suppress the publish-failure warning', () => {
    const channel = uniqueChannel()
    const bus = makeFailingBus()
    const inv = createIamRedisInvalidator({ channel, client: bus, secret: 'shared-secret' })
    inv.subscribe(() => {})

    // The attacker's move: one message, claiming the channel's warn window.
    bus.deliver(JSON.stringify({ event: { kind: 'all' }, instanceId: 'peer' }))
    // The operator's outage, in the same window.
    inv.publish({ kind: 'all' })

    const warns = warnSpy.mock.calls.map((c: unknown[]) => String(c[0]))
    expect(warns.filter((m: string) => /publish failed/.test(m))).toHaveLength(1)
    expect(warns.filter((m: string) => /unsigned message with secret configured/.test(m))).toHaveLength(1)
  })

  it('each kind still coalesces within its own window', () => {
    // The separation must not have cost the rate limiting it namespaces.
    const channel = uniqueChannel()
    const bus = makeFailingBus()
    const inv = createIamRedisInvalidator({ channel, client: bus, secret: 'shared-secret' })
    inv.subscribe(() => {})

    for (let i = 0; i < 5; i++) {
      bus.deliver(JSON.stringify({ event: { kind: 'all' }, instanceId: 'peer' }))
      inv.publish({ kind: 'all' })
    }

    const warns = warnSpy.mock.calls.map((c: unknown[]) => String(c[0]))
    expect(warns.filter((m: string) => /publish failed/.test(m))).toHaveLength(1)
    expect(warns.filter((m: string) => /unsigned message with secret configured/.test(m))).toHaveLength(1)
  })
})
