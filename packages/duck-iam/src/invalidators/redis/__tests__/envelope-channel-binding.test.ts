import { createHmac } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createIamRedisInvalidator, type IamRedisInvalidator } from '../index'

// SECURITY: a v2 envelope is bound to its signed channel, so another tenant's envelope is refused on a shared secret.
// Pre-v2 (unbound) envelopes are refused unless `acceptLegacyUnboundEnvelopes` is on.

function bus(): {
  client: IamRedisInvalidator.IPubSubLike
  deliver: (m: string) => void
  published: string[]
} {
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

const SECRET = 'one-secret-across-the-fleet'

/** Drop reports coalesce per channel for 60s at module scope, so each test needs its own tenant. */
let tenantSeq = 0
function uniqueTenant(name: string): string {
  tenantSeq += 1
  return `${name}-${tenantSeq}-${Math.random().toString(36).slice(2, 8)}`
}

/** The envelope a tenant publishes for a subject revoke. */
function envelopeFrom(tenantId: string, secret: string): string {
  const b = bus()
  createIamRedisInvalidator({ client: b.client, secret, tenantId }).publish({ kind: 'subject', subjectId: 'u1' })
  return b.published[0] ?? ''
}

/** What a tenant's node accepts when handed `wire`. */
function deliveredTo(
  tenantId: string,
  wire: string,
  opts: { acceptLegacyUnboundEnvelopes?: boolean } = {},
): { events: unknown[]; drops: string[] } {
  const b = bus()
  const events: unknown[] = []
  const drops: string[] = []
  const inv = createIamRedisInvalidator({
    client: b.client,
    onMessageDropped: (reason) => drops.push(reason),
    secret: SECRET,
    tenantId,
    ...opts,
  })
  inv.subscribe((e) => events.push(e))
  b.deliver(wire)
  return { events, drops }
}

describe('a signed envelope is bound to the channel it was signed for', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('control: a tenant accepts its own envelope', () => {
    // Guards against a node that accepts nothing.
    const t = uniqueTenant('acme')
    const { events, drops } = deliveredTo(t, envelopeFrom(t, SECRET))
    expect(events).toEqual([{ kind: 'subject', subjectId: 'u1' }])
    expect(drops).toEqual([])
  })

  it('a tenant refuses another tenant’s envelope relayed onto its channel', () => {
    const { events, drops } = deliveredTo(uniqueTenant('globex'), envelopeFrom(uniqueTenant('acme'), SECRET))
    expect(events).toEqual([])
    expect(drops).toEqual(['envelope was signed for a different channel'])
  })

  it('control: the signature itself still does its job', () => {
    // A wrong secret fails as a signature mismatch, so the case above tests the binding, not the HMAC.
    const t = uniqueTenant('acme')
    const { events, drops } = deliveredTo(t, envelopeFrom(t, 'a-different-secret'))
    expect(events).toEqual([])
    expect(drops).toEqual(['signature mismatch'])
  })

  it('the channel is inside the signed payload, not merely the topic', () => {
    const t = uniqueTenant('acme')
    const parsed: unknown = JSON.parse(envelopeFrom(t, SECRET))
    const payload = (parsed as { payload: { channel?: unknown }; v?: unknown }).payload
    expect((parsed as { v?: unknown }).v).toBe(2)
    expect(payload.channel).toBe(`duck-iam:invalidate:tenant:${t}`)
  })
})

describe('pre-v2 envelopes are refused unless the operator opts in', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    warnSpy.mockRestore()
  })

  /** A v1 envelope: correctly signed under the old, channel-free pre-image. */
  function legacyWire(): string {
    // Hand-built: the v1 pre-image is the payload without a `channel` key.
    const payload = { event: { kind: 'all' }, instanceId: 'old-node', ts: Date.now() }
    const canonical = `{"event":{"kind":"${payload.event.kind}"},"instanceId":"${payload.instanceId}","ts":${payload.ts}}`
    const sig = createHmac('sha256', SECRET).update(canonical).digest('hex')
    return JSON.stringify({ payload, sig, v: 1 })
  }

  it('drops a v1 envelope by default, naming the reason', () => {
    const { events, drops } = deliveredTo(uniqueTenant('acme'), legacyWire())
    expect(events).toEqual([])
    expect(drops).toEqual(['v:1 envelope is not channel-bound'])
  })

  it('accepts it under acceptLegacyUnboundEnvelopes, and says so at construction', () => {
    const { events, drops } = deliveredTo(uniqueTenant('acme'), legacyWire(), { acceptLegacyUnboundEnvelopes: true })
    expect(drops).toEqual([])
    expect(events).toEqual([{ kind: 'all' }])
    const said = warnSpy.mock.calls.map((c: unknown[]) => String(c[0])).join('\n')
    expect(said).toContain('acceptLegacyUnboundEnvelopes')
  })

  it('the opt-in is what re-opens the cross-tenant relay, which is why it warns', () => {
    // A v1 envelope carries no channel, so under the flag nothing is left to compare.
    const { events } = deliveredTo(uniqueTenant('globex'), legacyWire(), { acceptLegacyUnboundEnvelopes: true })
    expect(events).toEqual([{ kind: 'all' }])
  })
})
