import { describe, expect, it, vi } from 'vitest'
import type { Identity } from '../../../core/types/identity'
import { AuthConsoleChannel, AuthNoopChannel, AuthTestChannel } from '../index'

function makeIdentity(): Identity.Me<unknown> {
  return {
    id: 'ident-1',
    providers: [],
    emailVerified: false,
    version: 1,
    createdAt: new Date(0),
    updatedAt: new Date(0),
  }
}

describe('AuthConsoleChannel', () => {
  it('writes one JSON line per send', async () => {
    const sink = vi.fn()
    const ch = new AuthConsoleChannel({ sink })
    const result = await ch.send({
      identity: makeIdentity(),
      templateId: 'magic-link',
      vars: { url: 'https://app/click?t=...' },
      tenant: { tenantId: 'acme' },
    })
    expect(result.ok).toBe(true)
    expect(result.providerMessageId).toMatch(/^console:\d+:/)
    expect(sink).toHaveBeenCalledOnce()
    const parsed = JSON.parse(sink.mock.calls[0]![0]!)
    expect(parsed.templateId).toBe('magic-link')
    expect(parsed.identityId).toBe('ident-1')
    expect(parsed.tenantId).toBe('acme')
    expect(parsed.vars).toEqual({ url: 'https://app/click?t=...' })
  })

  it('uses kind from config (sms / webpush)', () => {
    expect(new AuthConsoleChannel({ kind: 'sms' }).kind).toBe('sms')
    expect(new AuthConsoleChannel({ kind: 'webpush' }).kind).toBe('webpush')
  })
})

describe('AuthNoopChannel', () => {
  it('discards every send + returns ok', async () => {
    const ch = new AuthNoopChannel()
    const result = await ch.send({
      identity: makeIdentity(),
      templateId: 'verify-email',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(true)
    expect(result.providerMessageId).toMatch(/^noop:/)
  })
})

describe('AuthTestChannel', () => {
  it('captures every send into outbox', async () => {
    const ch = new AuthTestChannel()
    await ch.send({
      identity: makeIdentity(),
      templateId: 'magic-link',
      vars: { url: 'x' },
      tenant: { tenantId: 'acme' },
    })
    await ch.send({
      identity: makeIdentity(),
      templateId: 'verify-email',
      vars: { code: '123' },
      tenant: {},
    })
    expect(ch.outbox).toHaveLength(2)
    expect(ch.outbox[0]!.templateId).toBe('magic-link')
    expect(ch.outbox[0]!.tenantId).toBe('acme')
    expect(ch.outbox[1]!.templateId).toBe('verify-email')
    expect(ch.outbox[1]!.tenantId).toBeNull()
  })
})
