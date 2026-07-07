import { describe, expect, it, vi } from 'vitest'
import type { Identity } from '../../../core/types/identity'
import { AuthResendChannel } from '../index'

function makeIdentity(email: string | undefined): Identity.Me {
  return {
    id: 'ident-1',
    tenantId: null,
    // Empty email string models the "no deliverable address" case; the channel
    // reads it via getProfileString, which treats '' as absent (returns ok:false).
    profile: { username: 'u', email: email ?? '' },
    providers: [],
    emailVerified: false,
    version: 1,
    createdAt: new Date(0),
    updatedAt: new Date(0),
    deletedAt: null,
  }
}

function makeClient(impl?: AuthResendChannel.IClient['emails']['send']): AuthResendChannel.IClient {
  return {
    emails: {
      send: vi.fn(impl ?? (async () => ({ data: { id: 'rs-1' }, error: null }))),
    },
  }
}

describe('AuthResendChannel', () => {
  it('happy path: resolves template + delegates to client.emails.send', async () => {
    const client = makeClient()
    const channel = new AuthResendChannel({
      from: 'noreply@app.test',
      client,
      templates: () => ({ subject: 'Welcome', html: '<p>Hi</p>' }),
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'welcome',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(true)
    expect(result.providerMessageId).toBe('rs-1')
    expect(client.emails.send).toHaveBeenCalledWith(
      expect.objectContaining({ from: 'noreply@app.test', to: 'user@x.com', subject: 'Welcome' }),
    )
  })

  it('refuses construction without from', () => {
    expect(
      () =>
        new AuthResendChannel({
          from: '',
          client: makeClient(),
          templates: () => ({ subject: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('refuses construction without apiKey or client', () => {
    expect(
      () =>
        new AuthResendChannel({
          from: 'noreply@app.test',
          templates: () => ({ subject: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('returns ok:false when identity has no email', async () => {
    const channel = new AuthResendChannel({
      from: 'noreply@app.test',
      client: makeClient(),
      templates: () => ({ subject: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity(undefined),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toMatch(/no email/)
  })

  it('surfaces Resend errors verbatim on ok:false', async () => {
    const channel = new AuthResendChannel({
      from: 'noreply@app.test',
      client: makeClient(async () => ({ data: null, error: { message: 'domain-not-verified' } })),
      templates: () => ({ subject: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toBe('domain-not-verified')
  })

  it('catches thrown client errors as ok:false', async () => {
    const channel = new AuthResendChannel({
      from: 'noreply@app.test',
      client: makeClient(async () => {
        throw new Error('network')
      }),
      templates: () => ({ subject: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('network')
  })

  it('template resolver throw becomes ok:false', async () => {
    const channel = new AuthResendChannel({
      from: 'noreply@app.test',
      client: makeClient(),
      templates: () => {
        throw new Error('template-missing')
      },
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('template-missing')
  })
})
