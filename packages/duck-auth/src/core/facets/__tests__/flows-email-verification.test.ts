import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthTestChannel } from '../../../channels/console'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AuthEngine } from '../../engine'
import { AuthScryptHasher } from '../../password/scrypt'
import { AuthCookieTransport } from '../../transport/cookie'

interface MyProfile {
  email: string
  emailVerified?: boolean
}

function build() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 3, windowMs: 60_000 }),
    passwords: { hasher: new AuthScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
}

describe('FlowsFacet - email verification', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string
  let channel: AuthTestChannel

  beforeEach(async () => {
    ;({ auth, adapter } = build())
    const ident = await auth.identities.create({
      profile: { email: 'a@x.com', emailVerified: false },
    })
    identityId = ident.id
    channel = new AuthTestChannel()
  })

  it('request -> complete round-trips: identity.profile.emailVerified flips to true', async () => {
    await auth.flows.requestEmailVerification({
      identityId,
      channels: { email: channel },
    })
    expect(channel.outbox).toHaveLength(1)
    expect(channel.outbox[0]!.templateId).toBe('email-verification')
    const url = (channel.outbox[0]!.vars as { url: string }).url
    const token = new URL(url).searchParams.get('token')
    expect(token).toBeTruthy()
    await auth.flows.completeEmailVerification({ token: token! })
    const ident = await adapter.identities.findById(identityId, {})
    expect(ident?.profile?.emailVerified).toBe(true)
  })

  it('already-verified identity short-circuits: no token minted, channel quiet', async () => {
    await adapter.identities.update(identityId, { profile: { email: 'a@x.com', emailVerified: true } }, 1, {})
    const result = await auth.flows.requestEmailVerification({
      identityId,
      channels: { email: channel },
    })
    expect(result).toEqual({ ok: true })
    expect(channel.outbox).toHaveLength(0)
  })

  it('complete with bogus token throws RECOVERY_TOKEN_INVALID', async () => {
    await expect(auth.flows.completeEmailVerification({ token: 'not-a-real-token' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('complete with empty token throws RECOVERY_TOKEN_INVALID', async () => {
    await expect(auth.flows.completeEmailVerification({ token: '' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('complete is single-use: replay fails', async () => {
    await auth.flows.requestEmailVerification({ identityId, channels: { email: channel } })
    const url = (channel.outbox[0]!.vars as { url: string }).url
    const token = new URL(url).searchParams.get('token')!
    await auth.flows.completeEmailVerification({ token })
    await expect(auth.flows.completeEmailVerification({ token })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('rate-limit enforced (max 3 within window)', async () => {
    for (let i = 0; i < 3; i++) {
      await auth.flows.requestEmailVerification({ identityId, channels: { email: channel } })
    }
    await expect(
      auth.flows.requestEmailVerification({ identityId, channels: { email: channel } }),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
  })

  it('rejects request for unknown identity', async () => {
    await expect(
      auth.flows.requestEmailVerification({
        identityId: 'does-not-exist',
        channels: { email: channel },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('rejects request when configured channel is not supplied', async () => {
    await expect(
      auth.flows.requestEmailVerification({
        identityId,
        channel: 'sms',
        channels: { email: channel },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it('resend replaces the prior token (only the latest verifies)', async () => {
    await auth.flows.requestEmailVerification({ identityId, channels: { email: channel } })
    const firstToken = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.requestEmailVerification({ identityId, channels: { email: channel } })
    const secondToken = new URL((channel.outbox[1]!.vars as { url: string }).url).searchParams.get('token')!
    expect(firstToken).not.toBe(secondToken)
    await expect(auth.flows.completeEmailVerification({ token: firstToken })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
    await auth.flows.completeEmailVerification({ token: secondToken })
  })
})
