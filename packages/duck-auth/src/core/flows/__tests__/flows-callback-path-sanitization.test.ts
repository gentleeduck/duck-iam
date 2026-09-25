import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { authTestDeliver } from '~/test'

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
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
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

    it.each(ATTACKER_VALUES)('attacker callbackPath %p -> emailed URL stays on app.example.com', async (bad) => {
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

    it.each(ATTACKER_VALUES)('attacker callbackPath %p -> emailed URL stays on app.example.com', async (bad) => {
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

    it.each(ATTACKER_VALUES)('attacker callbackPath %p -> emailed URL stays on app.example.com', async (bad) => {
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
