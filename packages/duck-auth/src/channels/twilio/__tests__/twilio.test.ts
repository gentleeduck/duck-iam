import { describe, expect, it, vi } from 'vitest'
import type { AuthIdentity } from '../../../core/types/identity'
import { AuthTwilioChannel } from '../index'

function makeIdentity(phone: string | undefined): AuthIdentity.IIdentity<unknown> {
  return {
    id: 'ident-1',
    profile: phone ? { phone } : undefined,
    providers: [],
    version: 1,
    createdAt: 0,
    updatedAt: 0,
  }
}

function makeClient(impl?: AuthTwilioChannel.IClient['messages']['create']): AuthTwilioChannel.IClient {
  return {
    messages: {
      create: vi.fn(impl ?? (async () => ({ sid: 'SM1', errorCode: null, errorMessage: null }))),
    },
  }
}

describe('AuthTwilioChannel', () => {
  it('happy path: resolves template + sends via Twilio.messages.create', async () => {
    const client = makeClient()
    const channel = new AuthTwilioChannel({
      from: '+15550000000',
      client,
      templates: () => ({ body: 'Your code is 1234' }),
    })
    const result = await channel.send({
      identity: makeIdentity('+15551234567'),
      templateId: 'otp',
      vars: { code: '1234' },
      tenant: {},
    })
    expect(result.ok).toBe(true)
    expect(result.providerMessageId).toBe('SM1')
    expect(client.messages.create).toHaveBeenCalledWith({
      from: '+15550000000',
      to: '+15551234567',
      body: 'Your code is 1234',
    })
  })

  it('messagingServiceSid path bypasses from', async () => {
    const client = makeClient()
    const channel = new AuthTwilioChannel({
      messagingServiceSid: 'MGservice',
      client,
      templates: () => ({ body: 'x' }),
    })
    await channel.send({
      identity: makeIdentity('+15551234567'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(client.messages.create).toHaveBeenCalledWith(
      expect.objectContaining({ messagingServiceSid: 'MGservice', to: '+15551234567' }),
    )
  })

  it('refuses construction when both from + messagingServiceSid supplied', () => {
    expect(
      () =>
        new AuthTwilioChannel({
          from: '+1',
          messagingServiceSid: 'MG',
          client: makeClient(),
          templates: () => ({ body: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('refuses construction when neither from nor messagingServiceSid', () => {
    expect(
      () =>
        new AuthTwilioChannel({
          client: makeClient(),
          templates: () => ({ body: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('refuses construction when neither client nor credentials supplied', () => {
    expect(
      () =>
        new AuthTwilioChannel({
          from: '+1',
          templates: () => ({ body: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('returns ok:false when identity has no phone', async () => {
    const channel = new AuthTwilioChannel({
      from: '+1',
      client: makeClient(),
      templates: () => ({ body: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity(undefined),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toMatch(/no phone/)
  })

  it('surfaces Twilio errorMessage on ok:false', async () => {
    const channel = new AuthTwilioChannel({
      from: '+1',
      client: makeClient(async () => ({
        sid: undefined,
        errorCode: 21408,
        errorMessage: 'Permission to send an SMS has not been enabled for the region',
      })),
      templates: () => ({ body: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity('+15551234567'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('region')
  })

  it('catches thrown client errors as ok:false', async () => {
    const channel = new AuthTwilioChannel({
      from: '+1',
      client: makeClient(async () => {
        throw new Error('network-timeout')
      }),
      templates: () => ({ body: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity('+15551234567'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('network-timeout')
  })

  it('template resolver throw becomes ok:false', async () => {
    const channel = new AuthTwilioChannel({
      from: '+1',
      client: makeClient(),
      templates: () => {
        throw new Error('template-missing')
      },
    })
    const result = await channel.send({
      identity: makeIdentity('+15551234567'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('template-missing')
  })
})
