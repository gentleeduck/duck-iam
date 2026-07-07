import { describe, expect, it, vi } from 'vitest'
import type { Identity } from '../../../core/types/identity'
import { AuthWebPushChannel } from '../index'

const SUB: AuthWebPushChannel.ISubscription = {
  endpoint: 'https://fcm.googleapis.com/x',
  keys: { p256dh: 'PUBLIC', auth: 'AUTH' },
}

function makeIdentity(subscription: AuthWebPushChannel.ISubscription | undefined): Identity.Me {
  return {
    id: 'ident-1',
    tenantId: null,
    // Subscription omitted models the "no push endpoint" case (channel returns ok:false).
    profile: subscription
      ? { username: 'u', email: 'u@x.com', pushSubscription: subscription }
      : { username: 'u', email: 'u@x.com' },
    providers: [],
    emailVerified: false,
    version: 1,
    createdAt: new Date(0),
    updatedAt: new Date(0),
    deletedAt: null,
  }
}

function makeModule(impl?: AuthWebPushChannel.IModule['sendNotification']): AuthWebPushChannel.IModule {
  return {
    setVapidDetails: vi.fn(),
    sendNotification: vi.fn(impl ?? (async () => ({ statusCode: 201 }))),
  }
}

const CFG_BASE = {
  subject: 'mailto:ops@app.test',
  publicKey: 'PUB',
  privateKey: 'PRIV',
}

describe('AuthWebPushChannel', () => {
  it('happy path: configures VAPID + sends notification', async () => {
    const mod = makeModule()
    const channel = new AuthWebPushChannel({
      ...CFG_BASE,
      module: mod,
      templates: () => ({ payload: JSON.stringify({ title: 'Hi' }) }),
    })
    const result = await channel.send({
      identity: makeIdentity(SUB),
      templateId: 'notify',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(true)
    expect(result.providerMessageId).toBe('webpush:201')
    expect(mod.setVapidDetails).toHaveBeenCalledWith('mailto:ops@app.test', 'PUB', 'PRIV')
    expect(mod.sendNotification).toHaveBeenCalledWith(SUB, JSON.stringify({ title: 'Hi' }), expect.any(Object))
  })

  it('refuses construction without VAPID details', () => {
    expect(
      () =>
        new AuthWebPushChannel({ subject: '', publicKey: 'X', privateKey: 'Y', templates: () => ({ payload: '' }) }),
    ).toThrowError(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('returns ok:false when identity has no pushSubscription', async () => {
    const channel = new AuthWebPushChannel({
      ...CFG_BASE,
      module: makeModule(),
      templates: () => ({ payload: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity(undefined),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toMatch(/pushSubscription/)
  })

  it('returns ok:false when subscription keys are missing', async () => {
    const channel = new AuthWebPushChannel({
      ...CFG_BASE,
      module: makeModule(),
      templates: () => ({ payload: 'x' }),
    })
    const broken: AuthWebPushChannel.ISubscription = {
      endpoint: 'https://x',
      keys: { p256dh: '', auth: '' },
    }
    const result = await channel.send({
      identity: makeIdentity(broken),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
  })

  it('catches sendNotification throws as ok:false with statusCode prefix when available', async () => {
    const channel = new AuthWebPushChannel({
      ...CFG_BASE,
      module: makeModule(async () => {
        const err = new Error('subscription has expired')
        ;(err as { statusCode?: number }).statusCode = 410
        throw err
      }),
      templates: () => ({ payload: 'x' }),
    })
    const result = await channel.send({
      identity: makeIdentity(SUB),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toBe('410:subscription has expired')
  })

  it('template resolver throw becomes ok:false', async () => {
    const channel = new AuthWebPushChannel({
      ...CFG_BASE,
      module: makeModule(),
      templates: () => {
        throw new Error('template-missing')
      },
    })
    const result = await channel.send({
      identity: makeIdentity(SUB),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('template-missing')
  })

  it('TTL from template forwarded to sendNotification', async () => {
    const mod = makeModule()
    const channel = new AuthWebPushChannel({
      ...CFG_BASE,
      module: mod,
      templates: () => ({ payload: 'x', ttl: 3600 }),
    })
    await channel.send({
      identity: makeIdentity(SUB),
      templateId: 'x',
      vars: {},
      tenant: {},
    })
    expect(mod.sendNotification).toHaveBeenCalledWith(SUB, 'x', expect.objectContaining({ TTL: 3600 }))
  })
})
