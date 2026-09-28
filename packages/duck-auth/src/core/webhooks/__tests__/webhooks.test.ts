import { describe, expect, it } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import { makeIdentity } from '~/test/store-inputs'
import { signWebhookBody, verifyWebhookSignature, WebhookDeliverer } from '../index'

/** A fetch answering `responses` in turn, the last one repeating, and what each request carried. */
function makeFetch(responses: Array<{ ok: boolean; throws?: boolean }>) {
  const calls: Array<{ url: string; body: string; headers: Headers }> = []
  let i = 0
  const fetch: typeof globalThis.fetch = async (url, opts) => {
    const r = responses[i++] ?? responses[responses.length - 1]
    calls.push({ body: String(opts?.body ?? ''), headers: new Headers(opts?.headers), url: String(url) })
    if (!r || r.throws) throw new Error('network-down')
    return new Response(null, { status: r.ok ? 200 : 500 })
  }
  return { calls, fetch }
}

describe('AuthWebhookDeliverer', () => {
  it('refuses construction without endpoints', () => {
    expect(() => new WebhookDeliverer({ endpoints: [] })).toThrowError(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('refuses construction when an endpoint is missing url or secret', () => {
    expect(() => new WebhookDeliverer({ endpoints: [{ url: '', secret: 'x' }] })).toThrowError(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it.each([
    ['a misspelt event name', '["sigin.success"]'],
    ['a string other than *', '"all"'],
  ])('refuses an endpoint subscribed to %s', (_, events) => {
    expect(
      () =>
        new WebhookDeliverer({ endpoints: [{ url: 'https://hook.test', secret: 's', events: JSON.parse(events) }] }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('delivers to an endpoint subscribed by name and to one subscribed to every event', async () => {
    const { calls, fetch } = makeFetch([{ ok: true }])
    const bus = new InMemoryEvents()
    const d = new WebhookDeliverer({
      endpoints: [
        { url: 'https://named.test', secret: 's', events: ['lockout'] },
        { url: 'https://every.test', secret: 's', events: '*' },
      ],
      fetch,
    })
    d.attach(bus)
    await bus.emit('lockout', { identityId: 'u1', until: 0 })
    await d.drain()
    expect(calls.map((c) => c.url).sort()).toEqual(['https://every.test', 'https://named.test'])
  })

  it('attach + emit delivers a signed POST to the endpoint', async () => {
    const { calls, fetch } = makeFetch([{ ok: true }])
    const bus = new InMemoryEvents()
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test/duck', secret: 'super-secret' }],
      backoffMs: 1,
      fetch,
    })
    d.attach(bus)
    await bus.emit('signin.success', {
      identity: makeIdentity({ id: 'u1' }),
      factors: [{ method: 'password', completedAt: new Date(0) }],
    })
    await d.drain()
    expect(calls).toHaveLength(1)
    expect(calls[0]!.url).toBe('https://hook.test/duck')
    const body = JSON.parse(calls[0]!.body)
    expect(body.event).toBe('signin.success')
    expect(body.payload.identity.id).toBe('u1')
    expect(calls[0]!.headers.get('X-Duck-Signature')).toMatch(/^authSha256=[a-f0-9]{64}$/)
  })

  it('filters by per-endpoint events list', async () => {
    const a = makeFetch([{ ok: true }])
    const b = makeFetch([{ ok: true }])
    const bus = new InMemoryEvents()
    const toA = new WebhookDeliverer({
      endpoints: [{ url: 'https://a.test', secret: 's', events: ['lockout'] }],
      fetch: a.fetch,
    })
    const toB = new WebhookDeliverer({
      endpoints: [{ url: 'https://b.test', secret: 's', events: ['signin.success'] }],
      fetch: b.fetch,
    })
    toA.attach(bus)
    toB.attach(bus)
    await bus.emit('lockout', { identityId: 'u1', until: 0 })
    await Promise.all([toA.drain(), toB.drain()])
    expect(a.calls).toHaveLength(1)
    expect(b.calls).toHaveLength(0)
  })

  it('retries up to maxAttempts, succeeds on a later attempt', async () => {
    const { calls, fetch } = makeFetch([
      { ok: false }, // attempt 1
      { ok: false }, // attempt 2
      { ok: true }, // attempt 3
    ])
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test', secret: 's' }],
      maxAttempts: 5,
      backoffMs: 1,
      fetch,
    })
    await d.deliverOne('lockout', { identityId: 'u1', until: 0 })
    expect(calls).toHaveLength(3)
  })

  it('dead-letters after exhausting attempts', async () => {
    const { fetch } = makeFetch([{ ok: false }, { ok: false }, { throws: true, ok: false }])
    const dlq: WebhookDeliverer.IDeadLetterEntry[] = []
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test', secret: 's', id: 'edge' }],
      maxAttempts: 3,
      backoffMs: 1,
      fetch,
      deadLetter: {
        put: async (entry) => {
          dlq.push(entry)
        },
      },
    })
    await d.deliverOne('lockout', { identityId: 'u1', until: 0 })
    expect(dlq).toHaveLength(1)
    expect(dlq[0]!.endpointId).toBe('edge')
    expect(dlq[0]!.attempts).toBe(3)
  })

  it('authSignWebhookBody + authVerifyWebhookSignature round-trip; rejects tampered body', () => {
    const body = JSON.stringify({ x: 1 })
    const sig = signWebhookBody('s', body)
    expect(verifyWebhookSignature('s', body, sig)).toBe(true)
    expect(verifyWebhookSignature('s', body + '!', sig)).toBe(false)
    expect(verifyWebhookSignature('different-secret', body, sig)).toBe(false)
  })

  it('honors custom signature header name', async () => {
    const { calls, fetch } = makeFetch([{ ok: true }])
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test', secret: 's', signatureHeader: 'X-My-Sig' }],
      fetch,
    })
    await d.deliverOne('lockout', { identityId: 'u1', until: 0 })
    expect(calls[0]!.headers.get('X-My-Sig')).toMatch(/^authSha256=/)
    expect(calls[0]!.headers.get('X-Duck-Signature')).toBeNull()
  })

  it('refuses non-HTTPS endpoint by default', () => {
    expect(
      () =>
        new WebhookDeliverer({
          endpoints: [{ url: 'http://hook.test', secret: 's' }],
        }),
    ).toThrowError(/AUTH_MISCONFIGURED/)
  })

  it.each([
    ['http://localhost/hook'],
    ['http://127.0.0.1/hook'],
    ['http://10.0.0.5/hook'],
    ['http://192.168.1.1/hook'],
    ['http://169.254.169.254/latest/meta-data/'],
    ['http://172.20.0.5/hook'],
  ])('refuses SSRF-risky host %s even with allowInsecure', (url) => {
    expect(
      () =>
        new WebhookDeliverer({
          endpoints: [{ url, secret: 's' }],
          allowInsecure: true,
        }),
    ).toThrowError(/AUTH_MISCONFIGURED/)
  })

  it.each([
    // IPv6 embedded-v4 forms that the legacy regex list missed.
    // WHATWG URL canonicalises `::ffff:127.0.0.1` -> `[::ffff:7f00:1]`,
    // and many OSes route this to the embedded v4 loopback.
    ['http://[::ffff:127.0.0.1]/hook', 'IPv4-mapped IPv6 loopback (dotted-quad form)'],
    ['http://[::ffff:7f00:1]/hook', 'IPv4-mapped IPv6 loopback (hex-tail canonical form)'],
    // NAT64 well-known prefix can carry inner v4 loopback.
    ['http://[64:ff9b::7f00:1]/hook', 'NAT64-wrapped loopback'],
    // 6to4 prefix routes to embedded inner v4 on Linux by default.
    ['http://[2002:7f00:1::]/hook', '6to4-wrapped loopback'],
    // all-zeros IPv6 unspecified often routes to local interface.
    ['http://[::]/hook', 'IPv6 unspecified (all-zeros)'],
    // hex-form IPv4 - WHATWG URL does NOT canonicalize 0x notation.
    ['http://0x7f.0.0.1/hook', 'hex-IPv4 loopback'],
  ])('refuses SSRF-risky host %s (%s)', (url) => {
    expect(
      () =>
        new WebhookDeliverer({
          endpoints: [{ url, secret: 's' }],
          allowInsecure: true,
        }),
    ).toThrowError(/AUTH_MISCONFIGURED/)
  })

  it('timestamp-bound signature round-trips + rejects replays outside window', async () => {
    const body = JSON.stringify({ x: 1 })
    const past = Date.now() - 10 * 60_000
    const sig = signWebhookBody('s', body, past)
    expect(verifyWebhookSignature('s', body, sig, { timestamp: past })).toBe(false)
    const fresh = Date.now()
    const sigFresh = signWebhookBody('s', body, fresh)
    expect(verifyWebhookSignature('s', body, sigFresh, { timestamp: fresh })).toBe(true)
  })

  it('deliverer emits X-Duck-Timestamp header alongside signature', async () => {
    const { calls, fetch } = makeFetch([{ ok: true }])
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test', secret: 's' }],
      fetch,
    })
    await d.deliverOne('lockout', { identityId: 'u1', until: 0 })
    expect(Number(calls[0]!.headers.get('x-duck-timestamp'))).toBeGreaterThan(0)
  })
})
