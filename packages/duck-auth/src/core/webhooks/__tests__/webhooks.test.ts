/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { describe, expect, it, vi } from 'vitest'
import { InMemoryEvents } from '../../events'
import { signWebhookBody, verifyWebhookSignature, type WebhookDeadLetterEntry, WebhookDeliverer } from '../index'

function makeFetch(
  responses: Array<{ ok: boolean; throws?: boolean }>,
): typeof globalThis.fetch & { calls: Array<{ url: string; body: string; headers: Record<string, string> }> } {
  const calls: Array<{ url: string; body: string; headers: Record<string, string> }> = []
  let i = 0
  const fn = vi.fn(async (url: string | URL | Request, opts?: RequestInit) => {
    const r = responses[i++] ?? responses[responses.length - 1]!
    calls.push({
      url: String(url),
      body: String(opts?.body ?? ''),
      headers: Object.fromEntries(Object.entries((opts?.headers as Record<string, string>) ?? {})),
    })
    if (r.throws) throw new Error('network-down')
    return { ok: r.ok } as Response
  }) as never
  ;(fn as { calls: typeof calls }).calls = calls
  return fn as never
}

describe('WebhookDeliverer', () => {
  it('refuses construction without endpoints', () => {
    expect(() => new WebhookDeliverer({ endpoints: [] })).toThrowError(
      expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }),
    )
  })

  it('refuses construction when an endpoint is missing url or secret', () => {
    expect(() => new WebhookDeliverer({ endpoints: [{ url: '', secret: 'x' }] })).toThrowError(
      expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }),
    )
  })

  it('attach + emit delivers a signed POST to the endpoint', async () => {
    const fetchStub = makeFetch([{ ok: true }])
    const bus = new InMemoryEvents()
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test/duck', secret: 'super-secret' }],
      backoffMs: 1,
      fetch: fetchStub,
    })
    d.attach(bus)
    await bus.emit('signin.success', {
      identity: { id: 'u1' } as never,
      factors: [{ method: 'password', completedAt: 0 }],
    })
    const calls = (
      fetchStub as unknown as { calls: Array<{ url: string; body: string; headers: Record<string, string> }> }
    ).calls
    expect(calls).toHaveLength(1)
    expect(calls[0]!.url).toBe('https://hook.test/duck')
    const body = JSON.parse(calls[0]!.body)
    expect(body.event).toBe('signin.success')
    expect(body.payload.identity.id).toBe('u1')
    expect(calls[0]!.headers['X-Duck-Signature']).toMatch(/^sha256=[a-f0-9]{64}$/)
  })

  it('filters by per-endpoint events list', async () => {
    const fetchA = makeFetch([{ ok: true }])
    const fetchB = makeFetch([{ ok: true }])
    const bus = new InMemoryEvents()
    new WebhookDeliverer({
      endpoints: [{ url: 'https://a.test', secret: 's', events: ['lockout'] }],
      fetch: fetchA,
    }).attach(bus)
    new WebhookDeliverer({
      endpoints: [{ url: 'https://b.test', secret: 's', events: ['signin.success'] }],
      fetch: fetchB,
    }).attach(bus)
    await bus.emit('lockout', { identityId: 'u1', until: 0 })
    expect((fetchA as unknown as { calls: unknown[] }).calls).toHaveLength(1)
    expect((fetchB as unknown as { calls: unknown[] }).calls).toHaveLength(0)
  })

  it('retries up to maxAttempts, succeeds on a later attempt', async () => {
    const fetchStub = makeFetch([
      { ok: false }, // attempt 1
      { ok: false }, // attempt 2
      { ok: true }, // attempt 3
    ])
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test', secret: 's' }],
      maxAttempts: 5,
      backoffMs: 1,
      fetch: fetchStub,
    })
    await d.deliverOne('lockout', { identityId: 'u1', until: 0 })
    expect((fetchStub as unknown as { calls: unknown[] }).calls.length).toBe(3)
  })

  it('dead-letters after exhausting attempts', async () => {
    const fetchStub = makeFetch([{ ok: false }, { ok: false }, { throws: true, ok: false }])
    const dlq: WebhookDeadLetterEntry[] = []
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test', secret: 's', id: 'edge' }],
      maxAttempts: 3,
      backoffMs: 1,
      fetch: fetchStub,
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

  it('signWebhookBody + verifyWebhookSignature round-trip; rejects tampered body', () => {
    const body = JSON.stringify({ x: 1 })
    const sig = signWebhookBody('s', body)
    expect(verifyWebhookSignature('s', body, sig)).toBe(true)
    expect(verifyWebhookSignature('s', body + '!', sig)).toBe(false)
    expect(verifyWebhookSignature('different-secret', body, sig)).toBe(false)
  })

  it('honors custom signature header name', async () => {
    const fetchStub = makeFetch([{ ok: true }])
    const d = new WebhookDeliverer({
      endpoints: [{ url: 'https://hook.test', secret: 's', signatureHeader: 'X-My-Sig' }],
      fetch: fetchStub,
    })
    await d.deliverOne('lockout', { identityId: 'u1', until: 0 })
    const calls = (fetchStub as unknown as { calls: Array<{ headers: Record<string, string> }> }).calls
    expect(calls[0]!.headers['X-My-Sig']).toBeDefined()
    expect(calls[0]!.headers['X-Duck-Signature']).toBeUndefined()
  })
})
