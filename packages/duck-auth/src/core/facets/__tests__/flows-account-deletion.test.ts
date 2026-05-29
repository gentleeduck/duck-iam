/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { TestChannel } from '../../../channels/console'
import { MemoryLimiter } from '../../../limiters/memory'
import { AuthRoot } from '../../auth'
import { ScryptHasher } from '../../password/scrypt'
import { CookieTransport } from '../../transport/cookie'

interface MyProfile {
  email: string
}

function build() {
  const adapter = new MemoryAuthAdapter<MyProfile>()
  const auth = new AuthRoot<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
}

describe('FlowsFacet - account deletion', () => {
  let auth: AuthRoot<MyProfile>
  let adapter: MemoryAuthAdapter<MyProfile>
  let identityId: string
  let channel: TestChannel

  beforeEach(async () => {
    ;({ auth, adapter } = build())
    const ident = await auth.identities.create({ profile: { email: 'a@x.com' } })
    identityId = ident.id
    channel = new TestChannel()
  })

  it('request -> complete soft-deletes the identity + revokes sessions + returns restorableUntil', async () => {
    // Pre-issue a session so we can assert it gets revoked.
    const { sid } = await auth.sessions.create({
      identityId,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: Date.now() }],
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
      code: 'AUTH/RECOVERY_TOKEN_INVALID',
    })
  })

  it('complete is single-use: replay fails', async () => {
    await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.completeAccountDeletion({ token })
    await expect(auth.flows.completeAccountDeletion({ token })).rejects.toMatchObject({
      code: 'AUTH/RECOVERY_TOKEN_INVALID',
    })
  })

  it('resend wipes the prior token; only latest verifies', async () => {
    await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    const t1 = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    const t2 = new URL((channel.outbox[1]!.vars as { url: string }).url).searchParams.get('token')!
    expect(t1).not.toBe(t2)
    await expect(auth.flows.completeAccountDeletion({ token: t1 })).rejects.toMatchObject({
      code: 'AUTH/RECOVERY_TOKEN_INVALID',
    })
    await auth.flows.completeAccountDeletion({ token: t2 })
  })

  it('rejects request for unknown identity', async () => {
    await expect(
      auth.flows.requestAccountDeletion({
        identityId: 'does-not-exist',
        channels: { email: channel },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/UNAUTHENTICATED' })
  })

  it('rejects request when configured channel is missing', async () => {
    await expect(
      auth.flows.requestAccountDeletion({
        identityId,
        channel: 'sms',
        channels: { email: channel },
      }),
    ).rejects.toMatchObject({ code: 'AUTH/MISCONFIGURED' })
  })

  it('rate-limit enforced (max 5 within window)', async () => {
    for (let i = 0; i < 5; i++) {
      await auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })
    }
    await expect(auth.flows.requestAccountDeletion({ identityId, channels: { email: channel } })).rejects.toMatchObject(
      { code: 'AUTH/RATE_LIMITED' },
    )
  })
})
