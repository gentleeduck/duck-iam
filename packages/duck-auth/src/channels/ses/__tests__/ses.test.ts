import { describe, expect, it, vi } from 'vitest'
import type { Identities } from '~/core/identities/identities.types'
import { AuthSesChannel } from '../index'

function makeIdentity(email: string | undefined): Identities.Me {
  return {
    createdBy: null,
    updatedBy: null,
    id: 'ident-1',
    // Empty email string models the "no deliverable address" case; the channel
    // reads it via getProfileString, which treats '' as absent (returns ok:false).
    profile: { username: 'u', email: email ?? '' },
    providers: [],
    emailVerified: false,
    version: 1,
    createdAt: new Date(Date.now()),
    updatedAt: new Date(Date.now()),
    deletedAt: null,
    deletedBy: null,
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
          templates: () => ({ subject: 'x', text: 'body' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('refuses construction without client', () => {
    expect(
      () =>
        new AuthSesChannel({
          client: null as unknown as AuthSesChannel.IClient,
          from: 'noreply@app.test',
          templates: () => ({ subject: 'x', text: 'body' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('returns ok:false when identity has no email', async () => {
    const channel = new AuthSesChannel({
      client: makeClient(),
      from: 'noreply@app.test',
      templates: () => ({ subject: 'x', text: 'body' }),
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

  it('names the configuration set the way SES spells it', async () => {
    // A find-and-replace had shortened the key to `CfgurationSetName`, which SES does not know, so
    // every feedback notification the set exists for was silently not configured.
    const seen: Array<{ input: Record<string, unknown> }> = []
    const channel = new AuthSesChannel({
      client: {
        send: async (command) => {
          seen.push(command as { input: Record<string, unknown> })
          return { MessageId: 'ses-1' }
        },
      },
      configurationSetName: 'auth-notifications',
      from: 'noreply@app.test',
      templates: () => ({ subject: 'x', text: 'y' }),
    })
    await channel.send({ identity: makeIdentity('user@x.com'), templateId: 'x', tenant: {}, vars: {} })
    expect(seen[0]?.input).toMatchObject({ ConfigurationSetName: 'auth-notifications' })
  })

  it('delivers through an injected client with the SDK absent from the workspace', async () => {
    // @aws-sdk/client-ses is not installed here, and a caller who supplied a client should not
    // need it: the command class is only an envelope around the request this builds.
    const client = makeClient()
    const channel = new AuthSesChannel({
      client,
      from: 'noreply@app.test',
      templates: () => ({ subject: 'x', text: 'y' }),
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(true)
  })
})
