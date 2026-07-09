import { describe, expect, it, vi } from 'vitest'
import type { Identity } from '~/core/identities/identities.types'
import { AuthSesChannel } from '../index'

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
    createdAt: new Date(Date.now()),
    updatedAt: new Date(Date.now()),
    deletedAt: null,
  }
}

function makeClient(impl?: AuthSesChannel.IClient['send']): AuthSesChannel.IClient {
  return { send: vi.fn(impl ?? (async () => ({ MessageId: 'ses-1' }))) }
}

describe('AuthSesChannel', () => {
  it('refuses construction without from', () => {
    expect(
      () =>
        new AuthSesChannel({
          client: makeClient(),
          from: '',
          templates: () => ({ subject: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('refuses construction without client', () => {
    expect(
      () =>
        new AuthSesChannel({
          client: null as unknown as AuthSesChannel.IClient,
          from: 'noreply@app.test',
          templates: () => ({ subject: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('returns ok:false when identity has no email', async () => {
    const channel = new AuthSesChannel({
      client: makeClient(),
      from: 'noreply@app.test',
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

  it('template resolver throw becomes ok:false', async () => {
    const channel = new AuthSesChannel({
      client: makeClient(),
      from: 'noreply@app.test',
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

  it('SES SDK missing surfaces AUTH/MISCONFIGURED message via ok:false', async () => {
    // Without @aws-sdk/client-ses installed in this workspace, the
    // command import inside send() throws AUTH/MISCONFIGURED; the
    // channel catches + reports as ok:false so the caller sees it.
    const channel = new AuthSesChannel({
      client: makeClient(),
      from: 'noreply@app.test',
      templates: () => ({ subject: 'x', text: 'y' }),
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    // SDK missing surfaces as AUTH/MISCONFIGURED (Error.message = code);
    // the install-hint lives in the AuthError.meta.detail. The
    // channel boundary turns the throw into ok:false.error = message.
    expect(result.error).toContain('AUTH_MISCONFIGURED')
  })
})
