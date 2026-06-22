import { beforeEach, describe, expect, it } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthTestChannel } from '../../../channels/console'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AuthEngine } from '../../auth'
import { AuthScryptHasher } from '../../password/scrypt'
import { AuthCookieTransport } from '../../transport/cookie'

interface MyProfile {
  email: string
  emailVerified?: boolean
}

function build() {
  const adapter = new AuthMemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 50, windowMs: 60_000 }),
    passwords: { hasher: new AuthScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
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

function getUrlFromOutbox(channel: AuthTestChannel): URL {
  expect(channel.outbox).toHaveLength(1)
  const vars = channel.outbox[0]!.vars
  if (!vars || typeof vars !== 'object' || !('url' in vars) || typeof vars.url !== 'string') {
    throw new Error('expected outbox[0].vars.url to be a string')
  }
  return new URL(vars.url)
}

describe('FlowsFacet - callbackPath sanitization', () => {
  describe('requestPasswordReset', () => {
    let auth: AuthEngine<MyProfile>
    let channel: AuthTestChannel
    let findIdentityByEmail: (email: string) => Promise<{ id: string } | null>

    beforeEach(async () => {
      const built = build()
      auth = built.auth
      channel = new AuthTestChannel()
      const ident = await auth.identities.create({ profile: { email: 'victim@x.com' } })
      findIdentityByEmail = async () => ({ id: ident.id })
    })

    it.each(ATTACKER_VALUES)('attacker callbackPath %p -> emailed URL stays on app.example.com', async (bad) => {
      await auth.flows.requestPasswordReset({
        input: { email: 'victim@x.com', callbackPath: bad },
        findIdentityByEmail,
        channels: { email: channel },
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/auth/reset-password')
    })

    it('legitimate callbackPath flows through unchanged', async () => {
      await auth.flows.requestPasswordReset({
        input: { email: 'victim@x.com', callbackPath: '/custom/reset' },
        findIdentityByEmail,
        channels: { email: channel },
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/custom/reset')
    })
  })

  describe('requestEmailVerification', () => {
    let auth: AuthEngine<MyProfile>
    let identityId: string
    let channel: AuthTestChannel

    beforeEach(async () => {
      const built = build()
      auth = built.auth
      const ident = await auth.identities.create({ profile: { email: 'a@x.com', emailVerified: false } })
      identityId = ident.id
      channel = new AuthTestChannel()
    })

    it.each(ATTACKER_VALUES)('attacker callbackPath %p -> emailed URL stays on app.example.com', async (bad) => {
      await auth.flows.requestEmailVerification({
        identityId,
        channels: { email: channel },
        callbackPath: bad,
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/auth/verify-email')
    })

    it('legitimate callbackPath flows through unchanged', async () => {
      await auth.flows.requestEmailVerification({
        identityId,
        channels: { email: channel },
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
    let channel: AuthTestChannel

    beforeEach(async () => {
      const built = build()
      auth = built.auth
      const ident = await auth.identities.create({ profile: { email: 'a@x.com' } })
      identityId = ident.id
      channel = new AuthTestChannel()
    })

    it.each(ATTACKER_VALUES)('attacker callbackPath %p -> emailed URL stays on app.example.com', async (bad) => {
      await auth.flows.requestAccountDeletion({
        identityId,
        channels: { email: channel },
        callbackPath: bad,
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/auth/delete-account')
    })

    it('legitimate callbackPath flows through unchanged', async () => {
      await auth.flows.requestAccountDeletion({
        identityId,
        channels: { email: channel },
        callbackPath: '/custom/delete',
      })
      const url = getUrlFromOutbox(channel)
      expect(url.host).toBe('app.example.com')
      expect(url.pathname).toBe('/custom/delete')
    })
  })
})
