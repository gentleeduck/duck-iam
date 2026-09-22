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
  emailVerified?: boolean
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
    limiter: new MemoryLimiter({ max: 3, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  return { auth, adapter }
}

describe('FlowsImpl - email verification', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string
  let channel: AuthTestChannel

  beforeEach(async () => {
    ;({ auth, adapter } = build())
    const ident = await auth.identities.create({
      profile: { username: 'a@x.com', email: 'a@x.com' },
    })
    identityId = ident.id
    channel = new AuthTestChannel()
  })

  it('request -> complete round-trips: the emailVerified column flips to true', async () => {
    await auth.flows.requestEmailVerification({
      identityId,
      channels: { email: channel },
    })
    expect(channel.outbox).toHaveLength(1)
    expect(channel.outbox[0]!.templateId).toBe('email-verification')
    const url = (channel.outbox[0]!.vars as { url: string }).url
    const token = new URL(url).searchParams.get('token')
    expect(token).toBeTruthy()
    const done = await auth.flows.completeEmailVerification({ token: token! })
    // The verified row straight off the write that set the flag, so a caller
    // rendering the account afterwards needs no second read.
    expect(done.identity.emailVerified).toBe(true)
    expect(done.identity.id).toBe(done.identityId)
    const ident = await adapter.identities.find({ id: identityId })
    expect(ident?.emailVerified).toBe(true)
  })

  it('already-verified identity short-circuits: no token minted, channel quiet', async () => {
    await adapter.identities.update(identityId, { emailVerified: true }, 1)
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

  it('a second verification reading between the claim and the delete is refused', async () => {
    // The claim and the delete are two statements, with the identity write between them. The replay test
    // above never opens that window, because it runs the second call after the first has finished.
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
    await engine.flows.requestEmailVerification({ channels: { email: ch }, identityId: ident.id })
    const token = new URL((ch.outbox[0]?.vars as { url: string }).url).searchParams.get('token') as string
    const [row] = await ad.credentials.listByIdentity(ident.id, 'recovery', {})
    gatedId = row?.id ?? null

    const winner = engine.flows.completeEmailVerification({ token })
    await vi.waitFor(() => {
      if (calls === 0) throw new Error('the winner has not claimed the row yet')
    })

    await expect(engine.flows.completeEmailVerification({ token })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
    release()
    expect((await winner).identity.emailVerified).toBe(true)
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
