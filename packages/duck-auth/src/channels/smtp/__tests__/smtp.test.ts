import { describe, expect, it, vi } from 'vitest'
import type { Identity } from '~/core/identities/identities.types'
import { AuthSmtpChannel } from '../index'

function makeIdentity(email: string | undefined): Identity.Me {
  return {
    id: 'ident-1',
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

function makeTransporter(impl?: AuthSmtpChannel.ITransporter['sendMail']): AuthSmtpChannel.ITransporter {
  return {
    sendMail: vi.fn(impl ?? (async () => ({ messageId: 'mid-1' }))),
  }
}

describe('AuthSmtpChannel', () => {
  it('resolves the template + sends with the configured `from`', async () => {
    const transporter = makeTransporter()
    const channel = new AuthSmtpChannel({
      transporter,
      from: 'noreply@app.test',
      templates: () => ({ subject: 'Hi', html: '<p>Hi</p>' }),
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'magic-link',
      vars: { url: 'https://app/click' },
      tenant: {},
    })
    expect(result.ok).toBe(true)
    expect(result.providerMessageId).toBe('mid-1')
    expect(transporter.sendMail).toHaveBeenCalledWith(
      expect.objectContaining({
        from: 'noreply@app.test',
        to: 'user@x.com',
        subject: 'Hi',
        html: '<p>Hi</p>',
      }),
    )
  })

  it('refuses construction when from is empty', () => {
    expect(
      () =>
        new AuthSmtpChannel({
          transporter: makeTransporter(),
          from: '',
          templates: () => ({ subject: 'x' }),
        }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('returns ok:false when the identity has no email', async () => {
    const channel = new AuthSmtpChannel({
      transporter: makeTransporter(),
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

  it('returns ok:false when the template resolver throws', async () => {
    const channel = new AuthSmtpChannel({
      transporter: makeTransporter(),
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

  it('returns ok:false when the transporter throws', async () => {
    const channel = new AuthSmtpChannel({
      transporter: makeTransporter(async () => {
        throw new Error('smtp-timeout')
      }),
      from: 'noreply@app.test',
      templates: () => ({ subject: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('smtp-timeout')
  })

  it('passes through the resolved text body when html is absent', async () => {
    const transporter = makeTransporter()
    const channel = new AuthSmtpChannel({
      transporter,
      from: 'noreply@app.test',
      templates: () => ({ subject: 'x', text: 'plain text body' }),
    })
    await channel.send({
      identity: makeIdentity('user@x.com'),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(transporter.sendMail).toHaveBeenCalledWith(expect.objectContaining({ text: 'plain text body' }))
  })
})
