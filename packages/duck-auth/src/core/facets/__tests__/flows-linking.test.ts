import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AuthEngine } from '../../engine'
import { AuthScryptHasher } from '../../password/scrypt'
import { AuthCookieTransport } from '../../transport/cookie'

interface MyProfile {
  email: string
}

function buildAuth(): {
  auth: AuthEngine<MyProfile>
  adapter: AuthMemoryAdapter<MyProfile>
} {
  const adapter = new AuthMemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 20, windowMs: 60_000 }),
    passwords: { hasher: new AuthScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
}

describe('FlowsFacet - account linking', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: AuthMemoryAdapter<MyProfile>
  let identityA: string
  let identityB: string

  beforeEach(async () => {
    ;({ auth, adapter } = buildAuth())
    const a = await auth.identities.create({ profile: { email: 'a@x.com' } })
    identityA = a.id
    const b = await auth.identities.create({ profile: { email: 'b@x.com' } })
    identityB = b.id
  })

  it('linkProvider attaches the provider link + emits identity.linked', async () => {
    const handler = vi.fn()
    auth.events.on('identity.linked', handler)
    const result = await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'authGoogle|111',
    })
    expect(result).toEqual({ identityId: identityA, providerId: 'authGoogle' })
    expect(handler).toHaveBeenCalledOnce()
    const ident = await adapter.identities.findById(identityA, {})
    expect(ident?.providers).toEqual([
      expect.objectContaining({ providerId: 'authGoogle', providerSub: 'authGoogle|111' }),
    ])
  })

  it('linkProvider is idempotent on the same (identityId, providerSub) pair', async () => {
    await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'authGoogle|111',
    })
    await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'authGoogle|111',
    })
    const ident = await adapter.identities.findById(identityA, {})
    expect(ident?.providers).toHaveLength(1)
  })

  it('linkProvider refuses when the sub already belongs to another identity', async () => {
    await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'authGoogle|111',
    })
    await expect(
      auth.flows.linkProvider({
        identityId: identityB,
        providerId: 'authGoogle',
        providerSub: 'authGoogle|111',
      }),
    ).rejects.toMatchObject({ code: 'AUTH/PROVIDER_FAILED' })
  })

  it('linkProvider rejects unknown identity', async () => {
    await expect(
      auth.flows.linkProvider({
        identityId: 'does-not-exist',
        providerId: 'authGoogle',
        providerSub: 'authGoogle|111',
      }),
    ).rejects.toMatchObject({ code: 'AUTH/UNAUTHENTICATED' })
  })

  it('unlinkProvider removes the link', async () => {
    await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'authGoogle|111',
    })
    // Add a password credential so the lockout guard does not trip.
    await adapter.credentials.upsert({ identityId: identityA, kind: 'password', secret: 'hashedXYZ' }, {})
    await auth.flows.unlinkProvider({ identityId: identityA, providerId: 'authGoogle' })
    const ident = await adapter.identities.findById(identityA, {})
    expect(ident?.providers).toEqual([])
  })

  it('unlinkProvider refuses when removing would leave zero factors', async () => {
    await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'authGoogle|111',
    })
    await expect(auth.flows.unlinkProvider({ identityId: identityA, providerId: 'authGoogle' })).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
    })
  })

  it('unlinkProvider with allowLockout:true bypasses the lockout guard', async () => {
    await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'authGoogle|111',
    })
    await auth.flows.unlinkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      allowLockout: true,
    })
    const ident = await adapter.identities.findById(identityA, {})
    expect(ident?.providers).toEqual([])
  })

  it('unlinkProvider is a no-op for a provider that was never linked', async () => {
    const result = await auth.flows.unlinkProvider({
      identityId: identityA,
      providerId: 'authGithub',
    })
    expect(result).toEqual({ identityId: identityA, providerId: 'authGithub' })
  })
})
