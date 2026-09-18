import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthTestChannel } from '~/channels/console'
import type { Credential } from '~/core/credentials'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function build(opts: { credentials?: (base: Credential.Store) => Credential.Store } = {}) {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: opts.credentials?.(adapter.credentials) ?? adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  return { auth, adapter }
}

describe('FlowsImpl - account deletion', () => {
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
    await expect(auth.sessions.getBySid(sid)).resolves.toBeDefined()

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
    // The deadline is read off the row the store wrote, not a second reading
    // of the clock, so the two can never disagree.
    expect(result.identity.deletedAt?.getTime()).toBe(result.restorableUntil)
    // The hidden row itself comes back: `findById` will not answer for it any
    // more, so this is the caller's only look at what was deleted.
    expect(result.identity.id).toBe(identityId)
    expect(result.identity.emailVerified).toBe(false)

    // Identity hidden from finds + sessions revoked.
    await expect(adapter.identities.find({ id: identityId })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
    await expect(auth.sessions.getBySid(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('cancel within grace restores the identity', async () => {
    await auth.flows.requestAccountDeletion({
      identityId,
      channels: { email: channel },
    })
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.completeAccountDeletion({ token })
    await expect(adapter.identities.find({ id: identityId })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })

    const cancelled = await auth.flows.cancelAccountDeletion({ authorize: async () => true, identityId })
    expect(cancelled.identity.id).toBe(identityId)
    expect(cancelled.identity.deletedAt).toBeNull()
    await expect(adapter.identities.find({ id: identityId })).resolves.toBeTruthy()
  })

  it('cancel refuses when authorize() says no, and leaves the account deleted', async () => {
    // The whole gate. Before this, the function checked that `identityId` was a
    // plausible string and restored the account - anyone who could reach it
    // un-deleted any account by id.
    await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId })
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.completeAccountDeletion({ token })

    await expect(auth.flows.cancelAccountDeletion({ authorize: async () => false, identityId })).rejects.toMatchObject({
      code: 'AUTH_UNAUTHENTICATED',
    })
    await expect(adapter.identities.find({ id: identityId })).rejects.toMatchObject({ code: 'AUTH_IDENTITY_NOT_FOUND' })
  })

  it('cancel asks authorize() about the identity it is being asked to restore', async () => {
    await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId })
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.completeAccountDeletion({ token })
    const seen: string[] = []

    await auth.flows.cancelAccountDeletion({
      authorize: async (id) => {
        seen.push(id)
        return true
      },
      identityId,
    })

    expect(seen).toEqual([identityId])
  })

  it('cancel refuses before reading or writing anything, not after', async () => {
    // A denial must not be observable as a restore-then-undo, and must not cost
    // a store round-trip an attacker can time.
    await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId })
    const token = new URL((channel.outbox[0]!.vars as { url: string }).url).searchParams.get('token')!
    await auth.flows.completeAccountDeletion({ token })
    const restore = vi.spyOn(adapter.identities, 'restore')

    await expect(auth.flows.cancelAccountDeletion({ authorize: async () => false, identityId })).rejects.toMatchObject({
      code: 'AUTH_UNAUTHENTICATED',
    })

    expect(restore).not.toHaveBeenCalled()
    restore.mockRestore()
  })

  it('a denied cancel is indistinguishable from an id that does not exist', async () => {
    // Same code both ways, so this cannot be used to ask which accounts are
    // sitting in the deletion grace window.
    const denied = await auth.flows
      .cancelAccountDeletion({ authorize: async () => false, identityId })
      .catch((e: unknown) => e)
    const unknown = await auth.flows
      .cancelAccountDeletion({ authorize: async () => true, identityId: 'no-such-identity' })
      .catch((e: unknown) => e)

    expect((denied as { code: string }).code).toBe('AUTH_UNAUTHENTICATED')
    expect((unknown as { code: string }).code).toBe('AUTH_UNAUTHENTICATED')
  })

  it('cancel without an authorize callback is a wiring error, not a silent pass', async () => {
    // TypeScript refuses this call; a JS host, or an object built from parsed
    // input, reaches it anyway. Reported as AUTH_MISCONFIGURED rather than
    // treated as permission granted.
    const input = { identityId } as unknown as Parameters<typeof auth.flows.cancelAccountDeletion>[0]
    await expect(auth.flows.cancelAccountDeletion(input)).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
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

  it('a second completion reading between the claim and the delete is refused', async () => {
    // The claim and the delete are two statements, with the soft delete and the session sweep between
    // them. A second completion in that window used to mint a second cancellation token - and mail it.
    let gatedId: string | null = null
    let calls = 0
    let release = (): void => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const { adapter: ad, auth: engine } = build({
      credentials: (base) => ({
        ...base,
        delete: async (id, ctx) => {
          if (id === gatedId) {
            calls += 1
            if (calls === 1) await held
          }
          return base.delete(id, ctx)
        },
      }),
    })
    const ident = await engine.identities.create({ profile: { username: 'b@x.com', email: 'b@x.com' } })
    const ch = new AuthTestChannel()
    await engine.flows.requestAccountDeletion({ channels: { email: ch }, identityId: ident.id })
    const token = new URL((ch.outbox[0]?.vars as { url: string }).url).searchParams.get('token') as string
    const [row] = await ad.credentials.listByIdentity(ident.id, 'recovery', {})
    gatedId = row?.id ?? null
    const softDeletes = vi.spyOn(ad.identities, 'softDelete')

    const winner = engine.flows.completeAccountDeletion({ channels: { email: ch }, token })
    await vi.waitFor(() => {
      if (calls === 0) throw new Error('the winner has not claimed the row yet')
    })

    await expect(engine.flows.completeAccountDeletion({ channels: { email: ch }, token })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
    release()
    await winner

    // Exactly one undo token exists, so exactly one undo link went out.
    const left = await ad.credentials.listByIdentity(ident.id, 'recovery', {})
    expect(left).toHaveLength(1)
    // The claim is what refuses the loser. Asserted separately because the soft delete would have caught
    // it one line later anyway, by reporting an already-hidden row as a miss - a guard in another file,
    // for another reason, which is not something this flow should be leaning on.
    expect(softDeletes).toHaveBeenCalledTimes(1)
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
