import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

// SECURITY: a signed envelope verifies for the whole 30s window, so without a seen-set anyone with channel
// access could repeat a captured one and wipe caches at will.

/** Mirrors `MAX_SEEN_SIGNATURES` in the invalidator. */
const SEEN_CAP = 5_000
const SECRET = 'one-secret-across-the-fleet'

function bus(): { client: IamRedisInvalidator.IPubSubLike; deliver: (m: string) => void; published: string[] } {
  let handler: ((m: string) => void) | null = null
  const published: string[] = []
  return {
    client: {
      publish(_c, m) {
        published.push(m)
      },
      subscribe(_c, h) {
        handler = h
      },
      unsubscribe() {},
    },
    deliver: (m) => handler?.(m),
    published,
  }
}

/** Drop reports coalesce per channel for 60s at module scope, so each test needs its own tenant. */
let tenantSeq = 0
function uniqueTenant(name: string): string {
  tenantSeq += 1
  return `${name}-${tenantSeq}-${Math.random().toString(36).slice(2, 8)}`
}

type Ev = { kind: 'subject'; subjectId: string }

/** A peer on `tenantId`'s channel; each call is a separate node, so envelopes are never self-published. */
function publisher(tenantId: string, secret: string | null): (event: Ev) => string {
  const b = bus()
  const inv = createIamRedisInvalidator({ client: b.client, secret, tenantId })
  return (event) => {
    inv.publish(event)
    const wire = b.published[b.published.length - 1]
    if (wire === undefined) throw new Error('publisher produced no wire message')
    return wire
  }
}

/** A subscribed node on `tenantId`'s channel, recording what it applies and what it drops. */
function node(tenantId: string, secret: string | null = SECRET) {
  const b = bus()
  const events: unknown[] = []
  const drops: string[] = []
  const inv = createIamRedisInvalidator({
    client: b.client,
    onMessageDropped: (reason) => drops.push(reason),
    secret,
    tenantId,
  })
  inv.subscribe((e) => events.push(e))
  return { deliver: b.deliver, drops, events }
}

describe('a signed envelope is applied at most once', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    warnSpy.mockRestore()
    vi.restoreAllMocks()
  })

  it('control: two distinct envelopes are both applied', () => {
    const t = uniqueTenant('acme')
    const wire = publisher(t, SECRET)
    const n = node(t)
    n.deliver(wire({ kind: 'subject', subjectId: 'u1' }))
    n.deliver(wire({ kind: 'subject', subjectId: 'u2' }))
    expect(n.events).toEqual([
      { kind: 'subject', subjectId: 'u1' },
      { kind: 'subject', subjectId: 'u2' },
    ])
    expect(n.drops).toEqual([])
  })

  it('the same envelope delivered twice is applied once, and the drop names the replay', () => {
    const t = uniqueTenant('acme')
    const captured = publisher(t, SECRET)({ kind: 'subject', subjectId: 'u1' })
    const n = node(t)
    n.deliver(captured)
    n.deliver(captured)
    expect(n.events).toEqual([{ kind: 'subject', subjectId: 'u1' }])
    expect(n.drops).toEqual(['replayed envelope (this signature was already applied)'])
  })

  it('a replay is refused however many times it is repeated, and however long the window has left', () => {
    const t = uniqueTenant('acme')
    const captured = publisher(t, SECRET)({ kind: 'subject', subjectId: 'u1' })
    const n = node(t)
    for (let i = 0; i < 20; i++) n.deliver(captured)
    expect(n.events).toEqual([{ kind: 'subject', subjectId: 'u1' }])
  })

  it('a replay is still refused after other envelopes have been applied in between', () => {
    const t = uniqueTenant('acme')
    const wire = publisher(t, SECRET)
    const captured = wire({ kind: 'subject', subjectId: 'u1' })
    const n = node(t)
    n.deliver(captured)
    n.deliver(wire({ kind: 'subject', subjectId: 'u2' }))
    n.deliver(wire({ kind: 'subject', subjectId: 'u3' }))
    n.deliver(captured)
    expect(n.events).toHaveLength(3)
    expect(n.drops).toEqual(['replayed envelope (this signature was already applied)'])
  })

  it('the same event from another node still applies, so it is the envelope that is deduped, not the event', () => {
    const t = uniqueTenant('acme')
    const n = node(t)
    n.deliver(publisher(t, SECRET)({ kind: 'subject', subjectId: 'u1' }))
    n.deliver(publisher(t, SECRET)({ kind: 'subject', subjectId: 'u1' }))
    expect(n.events).toHaveLength(2)
    expect(n.drops).toEqual([])
  })

  it('each node keeps its own set, so a second node still applies the envelope the first one saw', () => {
    const t = uniqueTenant('acme')
    const captured = publisher(t, SECRET)({ kind: 'subject', subjectId: 'u1' })
    const first = node(t)
    const second = node(t)
    first.deliver(captured)
    first.deliver(captured)
    second.deliver(captured)
    expect(first.events).toHaveLength(1)
    expect(second.events).toEqual([{ kind: 'subject', subjectId: 'u1' }])
  })

  it('one node publishing the same event twice within a millisecond dedupes, which is safe for a cache wipe', () => {
    const t = uniqueTenant('acme')
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000)
    const wire = publisher(t, SECRET)
    const n = node(t)
    n.deliver(wire({ kind: 'subject', subjectId: 'u1' }))
    n.deliver(wire({ kind: 'subject', subjectId: 'u1' }))
    expect(n.events).toEqual([{ kind: 'subject', subjectId: 'u1' }])
    expect(n.drops).toEqual(['replayed envelope (this signature was already applied)'])
  })

  it('the remembered set is capped, so a flood costs bounded memory and evicts the oldest', () => {
    const t = uniqueTenant('acme')
    const wire = publisher(t, SECRET)
    const n = node(t)
    const oldest = wire({ kind: 'subject', subjectId: 'u0' })
    n.deliver(oldest)
    for (let i = 1; i <= SEEN_CAP; i++) n.deliver(wire({ kind: 'subject', subjectId: `u${i}` }))
    const newest = wire({ kind: 'subject', subjectId: 'last' })
    n.deliver(newest)

    n.deliver(oldest)
    expect(n.events).toHaveLength(SEEN_CAP + 3)
    expect(n.drops).toEqual([])

    n.deliver(newest)
    expect(n.events).toHaveLength(SEEN_CAP + 3)
    expect(n.drops).toEqual(['replayed envelope (this signature was already applied)'])
  })

  it('an unsigned channel does not dedupe: nothing on it is authentic to begin with', () => {
    const t = uniqueTenant('unsigned')
    const captured = publisher(t, null)({ kind: 'subject', subjectId: 'u1' })
    const n = node(t, null)
    n.deliver(captured)
    n.deliver(captured)
    expect(n.events).toHaveLength(2)
    expect(n.drops).toEqual([])
  })
})
