/** The last-factor guard has two implementations - `flows.unlinkProvider` and `identities.unlink` - and
 *  they disagreed about what still authenticates an identity. Each let through a lockout the other caught. */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { RECOVERY_PURPOSES } from '~/core/credentials'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { credentialInput } from '~/test/store-inputs'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

const ALLOW_LINK = async () => true
const HOUR = 60 * 60 * 1000

describe('the last-factor guard, through both doors', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter<MyProfile>()
    auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
      providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
    identityId = ident.id
    // The one link being dropped: after it goes, the credentials are all that is left.
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId,
      providerId: 'authGoogle',
      providerSub: 'google-1',
    })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  /** Both doors onto the same act, so a case can be asserted against each without repeating itself. */
  const doors = [
    {
      name: 'flows.unlinkProvider',
      unlink: async () => (await auth.flows.unlinkProvider({ identityId, providerId: 'authGoogle' })).identity.id,
    },
    { name: 'identities.unlink', unlink: async () => (await auth.identities.unlink(identityId, 'authGoogle')).id },
  ] as const

  describe.each(doors)('$name', ({ unlink }) => {
    it('refuses when nothing else is left', async () => {
      await expect(unlink()).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('allows it when a live password remains', async () => {
      await adapter.credentials.create(credentialInput({ identityId, kind: 'password', secret: 'h' }), {})

      await expect(unlink()).resolves.toBe(identityId)
    })

    it('refuses when the only password left has been revoked', async () => {
      const row = await adapter.credentials.create(credentialInput({ identityId, kind: 'password', secret: 'h' }), {})
      await adapter.credentials.revoke(row.id, {})

      await expect(unlink()).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('refuses when the only password left has expired', async () => {
      await adapter.credentials.create(
        credentialInput({ expiresAt: new Date(Date.now() + HOUR), identityId, kind: 'password', secret: 'h' }),
        {},
      )
      // The store refuses to write a row that is already expired, so the expiry arrives the way it does in
      // production: the clock moves past it.
      vi.useFakeTimers()
      vi.setSystemTime(Date.now() + 2 * HOUR)

      // An expired credential signs nobody in, so counting it as a way back leaves the account unreachable.
      await expect(unlink()).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('refuses when the only thing left is a one-shot recovery token', async () => {
      await adapter.credentials.create(
        credentialInput({
          expiresAt: new Date(Date.now() + HOUR),
          identityId,
          kind: 'recovery',
          metadata: { purpose: RECOVERY_PURPOSES.passwordReset },
          secret: 'h',
        }),
        {},
      )

      // A reset token is spent once and gone; it is not a standing way into the account.
      await expect(unlink()).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('refuses when the only thing left is a second factor', async () => {
      await adapter.credentials.create(
        credentialInput({ identityId, kind: 'totp', metadata: { confirmed: true }, secret: 'JBSWY3DPEHPK3PXP' }),
        {},
      )

      await expect(unlink()).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('allows it when a live api key remains, which does start a session', async () => {
      await adapter.credentials.create(credentialInput({ identityId, kind: 'api-key', secret: 'h' }), {})

      await expect(unlink()).resolves.toBe(identityId)
    })
  })
})
