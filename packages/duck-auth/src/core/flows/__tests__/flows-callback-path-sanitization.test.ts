import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { authTestDataAtRest, authTestDeliver } from '~/test'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
  emailVerified?: boolean
}

function build() {
  const adapter = new MemoryAdapter<MyProfile>()
  const channel = authTestDeliver()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    deliver: channel.deliver,
    transport: new CookieTransport({ name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [
      passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }),
      mfaProvider({ dataAtRest: authTestDataAtRest() }),
    ],
  })
  return { adapter, auth, channel }
}

// Attacker-controlled callbackPath values that, without the guard,
// would rewrite the URL's host once concatenated with `${baseUrl}`.
const ATTACKER_VALUES: ReadonlyArray<string> = [
  '@evil.com',
  '@evil.com/grab',
  'evil.com',
  '//evil.com',
  '//evil.com/grab',
  '/\\evil.com',
  '/path\r\nLocation: https://evil.com',
]

function getUrlFromOutbox(channel: ReturnType<typeof authTestDeliver>): URL {
  expect(channel.outbox).toHaveLength(1)
  const vars = channel.outbox[0]!.vars
  if (!vars || typeof vars !== 'object' || !('url' in vars) || typeof vars.url !== 'string') {
    throw new Error('expected outbox[0].vars.url to be a string')
  }
  return new URL(vars.url)
}

describe('FlowsImpl - callbackPath sanitization', () => {
  describe('requestPasswordReset', () => {
    let auth: AuthEngine<MyProfile>
    let channel: ReturnType<typeof build>['channel']
    let findIdentityByEmail: (email: string) => Promise<{ id: string } | null>

    beforeEach(async () => {
      const built = build()
      auth = built.auth
      channel = built.channel
      const ident = await auth.identities.create({ profile: { username: 'victim@x.com', email: 'victim@x.com' } })
      findIdentityByEmail = async () => ({ id: ident.id })
    })

    it.each(ATTACKER_VALUES)('attacker callbackPath %o -> emailed URL stays on app.example.com', async (bad) => {
      await auth.flows.requestPasswordReset({
        input: { email: 'victim@x.com', callbackPath: bad },
        findIdentityByEmail,
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/auth/reset-password')
    })

    it('legitimate callbackPath flows through unchanged', async () => {
      await auth.flows.requestPasswordReset({
        input: { email: 'victim@x.com', callbackPath: '/custom/reset' },
        findIdentityByEmail,
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/custom/reset')
    })
  })

  describe('requestEmailVerification', () => {
    let auth: AuthEngine<MyProfile>
    let identityId: string
    let channel: ReturnType<typeof build>['channel']

    beforeEach(async () => {
      const built = build()
      auth = built.auth
      const ident = await auth.identities.create({
        profile: { username: 'a@x.com', email: 'a@x.com', emailVerified: false },
      })
      identityId = ident.id
      channel = built.channel
    })

    it.each(ATTACKER_VALUES)('attacker callbackPath %o -> emailed URL stays on app.example.com', async (bad) => {
      await auth.flows.requestEmailVerification({
        identityId,
        callbackPath: bad,
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/auth/verify-email')
    })

    it('legitimate callbackPath flows through unchanged', async () => {
      await auth.flows.requestEmailVerification({
        identityId,
        callbackPath: '/custom/verify',
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/custom/verify')
    })
  })

  describe('requestAccountDeletion', () => {
    let auth: AuthEngine<MyProfile>
    let identityId: string
    let channel: ReturnType<typeof build>['channel']

    beforeEach(async () => {
      const built = build()
      auth = built.auth
      const ident = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
      identityId = ident.id
      channel = built.channel
    })

    it.each(ATTACKER_VALUES)('attacker callbackPath %o -> emailed URL stays on app.example.com', async (bad) => {
      await auth.flows.requestAccountDeletion({
        identityId,
        callbackPath: bad,
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/auth/delete-account')
    })

    it('legitimate callbackPath flows through unchanged', async () => {
      await auth.flows.requestAccountDeletion({
        identityId,
        callbackPath: '/custom/delete',
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/custom/delete')
    })
  })
})

describe('FlowsImpl - a callbackPath that carries a query of its own', () => {
  function lastLink(channel: ReturnType<typeof authTestDeliver>): URL {
    const vars = channel.outbox.at(-1)?.vars
    if (!vars || typeof vars !== 'object' || !('url' in vars) || typeof vars.url !== 'string') {
      throw new Error('expected the last message to carry vars.url')
    }
    return new URL(vars.url)
  }

  it('mails a reset link that keeps the query and whose token resets the password', async () => {
    const { auth, channel } = build()
    const ident = await auth.identities.create({ profile: { username: 'r@x.com', email: 'r@x.com' } })
    await auth.flows.requestPasswordReset({
      input: { email: 'r@x.com', callbackPath: '/auth?mode=reset' },
      findIdentityByEmail: async () => ({ id: ident.id }),
    })
    const link = lastLink(channel)
    expect(link.pathname).toBe('/auth')
    expect(link.searchParams.get('mode')).toBe('reset')
    const token = link.searchParams.get('token') ?? ''
    await expect(
      auth.flows.completePasswordReset({ token, newPassword: 'a-long-new-passphrase-1' }),
    ).resolves.toMatchObject({
      ok: true,
    })
  })

  it('mails its own token in place of one the asker wrote into the path', async () => {
    const { auth, channel } = build()
    const ident = await auth.identities.create({ profile: { username: 'p@x.com', email: 'p@x.com' } })
    await auth.flows.requestPasswordReset({
      input: { email: 'p@x.com', callbackPath: '/auth?token=planted#reset' },
      findIdentityByEmail: async () => ({ id: ident.id }),
    })
    const link = lastLink(channel)
    expect(link.hash).toBe('#reset')
    const tokens = link.searchParams.getAll('token')
    expect(tokens).toHaveLength(1)
    expect(tokens[0]).not.toBe('planted')
    await expect(
      auth.flows.completePasswordReset({ token: tokens[0] ?? '', newPassword: 'a-long-new-passphrase-1' }),
    ).resolves.toMatchObject({ ok: true })
  })

  it('mails a verification link whose token verifies the address', async () => {
    const { auth, channel } = build()
    const ident = await auth.identities.create({
      profile: { username: 'v@x.com', email: 'v@x.com', emailVerified: false },
    })
    await auth.flows.requestEmailVerification({ identityId: ident.id, callbackPath: '/auth?mode=verify' })
    const link = lastLink(channel)
    expect(link.searchParams.get('mode')).toBe('verify')
    const done = await auth.flows.completeEmailVerification({ token: link.searchParams.get('token') ?? '' })
    expect(done.identityId).toBe(ident.id)
  })

  it('mails deletion and undo links whose tokens delete and restore the account', async () => {
    const { auth, channel } = build()
    const ident = await auth.identities.create({ profile: { username: 'd@x.com', email: 'd@x.com' } })
    await auth.flows.requestAccountDeletion({ identityId: ident.id, callbackPath: '/auth?mode=delete' })
    const confirm = lastLink(channel)
    expect(confirm.searchParams.get('mode')).toBe('delete')
    await auth.flows.completeAccountDeletion({
      token: confirm.searchParams.get('token') ?? '',
      sendUndoLink: true,
      callbackPath: '/auth?mode=undo',
    })
    const undo = lastLink(channel)
    expect(undo.searchParams.get('mode')).toBe('undo')
    const restored = await auth.flows.cancelAccountDeletion({ token: undo.searchParams.get('token') ?? '' })
    expect(restored.identityId).toBe(ident.id)
  })
})
