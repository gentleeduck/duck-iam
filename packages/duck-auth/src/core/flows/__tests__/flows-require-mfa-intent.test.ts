import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import type { Provider } from '~/core/provider/provider.types'
import { CookieTransport } from '~/core/transport/cookie.transport'

interface MyProfile extends Identities.ProfileMetadataBase {}

/**
 * `Provider.InternalIntent` declares `requireMfa` and the contract says `FlowsImpl` "consumes and
 * strips" it. Nothing shipped emits one, but the provider list is open, so a host-authored provider can
 * - and stripping without consuming turned its demand for a second factor into a plain sign-in.
 */
function providerEmitting(intents: Provider.InternalIntent[]): Provider.Me<unknown, unknown, MyProfile> {
  return {
    async begin() {
      return []
    },
    async complete() {
      return intents
    },
    id: 'demanding',
    kind: 'custom',
  }
}

async function buildAuth(intents: Provider.InternalIntent[]) {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    providers: [providerEmitting(intents)],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const identity = await adapter.identities.create({
    emailVerified: true,
    profile: { email: 'a@x.com', username: 'a' },
    providers: [],
  })
  return { auth, identityId: identity.id }
}

describe('a requireMfa intent is acted on, not dropped', () => {
  it('refuses to hand back a session when the provider also demanded a second factor', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const identity = await adapter.identities.create({
      emailVerified: true,
      profile: { email: 'a@x.com', username: 'a' },
      providers: [],
    })
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      providers: [
        providerEmitting([
          {
            aal: 1,
            factors: [{ completedAt: new Date(), method: 'password' }],
            identityId: identity.id,
            type: 'startSession',
          },
          { identityId: identity.id, methods: ['totp'], type: 'requireMfa' },
        ]),
      ],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    await expect(auth.flows.signIn({ input: {}, providerId: 'demanding' })).rejects.toMatchObject({
      code: 'AUTH_STEP_UP_REQUIRED',
    })
  })

  it('says so rather than answering an empty outcome when requireMfa arrives alone', async () => {
    const { auth, identityId } = await buildAuth([{ identityId: 'x', methods: ['totp'], type: 'requireMfa' }])
    expect(identityId).toBeTruthy()
    await expect(auth.flows.signIn({ input: {}, providerId: 'demanding' })).rejects.toMatchObject({
      code: 'AUTH_STEP_UP_REQUIRED',
    })
  })

  it('still signs in normally when no requireMfa is present', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const identity = await adapter.identities.create({
      emailVerified: true,
      profile: { email: 'b@x.com', username: 'b' },
      providers: [],
    })
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      providers: [
        providerEmitting([
          {
            aal: 1,
            factors: [{ completedAt: new Date(), method: 'password' }],
            identityId: identity.id,
            type: 'startSession',
          },
        ]),
      ],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    const out = await auth.flows.signIn({ input: {}, providerId: 'demanding' })
    expect(out.session?.identityId).toBe(identity.id)
  })
})
