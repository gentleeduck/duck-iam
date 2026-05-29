import { describe, expect, it, vi } from 'vitest'
import type { Identity } from '../../../core/types/identity'
import { SesChannel } from '../index'

function makeIdentity(email: string | undefined): Identity.IIdentity<unknown> {
  return {
    id: 'ident-1',
    profile: email ? { email } : undefined,
    providers: [],
    version: 1,
    createdAt: 0,
    updatedAt: 0,
  }
}

function makeClient(impl?: SesChannel.IClient['send']): SesChannel.IClient {
  return { send: vi.fn(impl ?? (async () => ({ MessageId: 'ses-1' }))) }
}

describe('SesChannel', () => {
  it('refuses construction without from', () => {
    expect(
      () =>
        new SesChannel({
          client: makeClient(),
          from: '',
          templates: () => ({ subject: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('refuses construction without client', () => {
    expect(
      () =>
        new SesChannel({
          client: null as unknown as SesChannel.IClient,
          from: 'noreply@app.test',
          templates: () => ({ subject: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }))
  })

  it('returns ok:false when identity has no email', async () => {
    const channel = new SesChannel({
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
    const channel = new SesChannel({
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
    const channel = new SesChannel({
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
    // the install-hint lives in the AuthErrorObject.meta.detail. The
    // channel boundary turns the throw into ok:false.error = message.
    expect(result.error).toContain('AUTH/MISCONFIGURED')
  })
})
