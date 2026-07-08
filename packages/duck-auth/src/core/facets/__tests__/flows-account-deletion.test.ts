import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthTestChannel } from '~/channels/console'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie'
import type { Identity } from '~/core/types/identity'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { passwordProvider } from '~/providers/password'
import { ScryptHasher } from '~/providers/password/hashers/scrypt.hasher'

interface MyProfile extends Identity.ProfileMetadataBase {
  email: string
}

function build() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwordProvider({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  return { auth, adapter }
}

describe('FlowsFacet - account deletion', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string
  let channel: AuthTestChannel

  beforeEach(async () => {
    ;({ auth, adapter } = build())
    const ident = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    identityId = ident.id
    channel = new AuthTestChannel()
  })

  it('request -> complete soft-deletes the identity + revokes sessions + returns restorableUntil', async () => {
    // Pre-issue a session so we can assert it gets revoked.
    const { sid } = await auth.sessions.create({
      identityId,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })
    expect(await auth.sessions.getBySid(sid)).not.toBeNull()

    await auth.flows.requestAccountDeletion({
      identityId,
      channels: { email: channel },
      reason: 'user request',
    })
    expect(channel.outbox).toHaveLength(1)
    expect(channel.outbox[0]!.templateId).toBe('account-deletion')
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!

    const result = await auth.flows.completeAccountDeletion({ token })
    expect(result.identityId).toBe(identityId)
    expect(result.restorableUntil).toBeGreaterThan(Date.now())

    // Identity hidden from finds + sessions revoked.
    expect(await adapter.identities.findById(identityId, {})).toBeNull()
    expect(await auth.sessions.getBySid(sid)).toBeNull()
  })

  it('cancel within grace restores the identity', async () => {
    await auth.flows.requestAccountDeletion({
      identityId,
      channels: { email: channel },
    })
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.completeAccountDeletion({ token })
    expect(await adapter.identities.findById(identityId, {})).toBeNull()

    await auth.flows.cancelAccountDeletion({ identityId })
    expect(await adapter.identities.findById(identityId, {})).not.toBeNull()
  })

  it('complete with bogus token throws RECOVERY_TOKEN_INVALID', async () => {
    await expect(auth.flows.completeAccountDeletion({ token: 'not-a-real-token' })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('complete is single-use: replay fails', async () => {
    await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.completeAccountDeletion({ token })
    await expect(auth.flows.completeAccountDeletion({ token })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('resend wipes the prior token; only latest verifies', async () => {
    await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    const t1 = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    const t2 = new URL((channel.outbox[1]!.vars as { url: string }).url).searchParams.get('token')!
    expect(t1).not.toBe(t2)
    await expect(auth.flows.completeAccountDeletion({ token: t1 })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
    await auth.flows.completeAccountDeletion({ token: t2 })
  })

  it('rejects request for unknown identity', async () => {
    await expect(
      auth.flows.requestAccountDeletion({
        identityId: 'does-not-exist',
        channels: { email: channel },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('rejects request when configured channel is missing', async () => {
    await expect(
      auth.flows.requestAccountDeletion({
        identityId,
        channel: 'sms',
        channels: { email: channel },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it('rate-limit enforced (max 5 within window)', async () => {
    for (let i = 0; i < 5; i++) {
      await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    }
    await expect(auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })).rejects.toMatchObject(
      { code: 'AUTH_RATE_LIMITED' },
    )
  })

  it('rejects oversize reason (>1024 chars)', async () => {
    const big = 'A'.repeat(1025)
    await expect(
      auth.flows.requestAccountDeletion({
        identityId,
        channels: { email: channel },
        reason: big,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it('accepts reason at 1024 chars (boundary)', async () => {
    const sized = 'A'.repeat(1024)
    const r = await auth.flows.requestAccountDeletion({
      identityId,
      channels: { email: channel },
      reason: sized,
    })
    expect(r).toEqual({ ok: true })
  })

  it('rejects non-string reason without crashing', async () => {
    await expect(
      auth.flows.requestAccountDeletion({
        identityId,
        channels: { email: channel },
        reason: 42 as unknown as string,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })
})
