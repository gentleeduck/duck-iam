import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { credentialInput } from '~/test/store-inputs'

/**
 * Stand-in for the host's proof that it completed the provider's dance. These
 * suites are about what `linkProvider` does once the caller is trusted; the
 * callback itself is exercised in `flows-c6-open-findings.test.ts`.
 */
const ALLOW_LINK = async () => true

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function buildAuth(): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  return { auth, adapter }
}

describe('FlowsImpl - account linking', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityA: string
  let identityB: string

  beforeEach(async () => {
    ;({ auth, adapter } = buildAuth())
    const a = await auth.identities.create({ profile: { username: 'a@x.com', email: 'a@x.com' } })
    identityA = a.id
    const b = await auth.identities.create({ profile: { username: 'b@x.com', email: 'b@x.com' } })
    identityB = b.id
  })

  it('linkProvider attaches the provider link + emits identity.linked', async () => {
    const handler = vi.fn()
    auth.events.on('identity.linked', handler)
    const result = await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    expect(result).toMatchObject({ identityId: identityA, providerId: 'google' })
    // The identity comes back off the write itself, already carrying the link.
    expect(result.identity.id).toBe(identityA)
    expect(result.identity.providers).toContainEqual(
      expect.objectContaining({ providerId: 'google', providerSub: 'google|111' }),
    )
    expect(handler).toHaveBeenCalledOnce()
    const ident = await adapter.identities.find({ id: identityA })
    expect(ident?.providers).toEqual([expect.objectContaining({ providerId: 'google', providerSub: 'google|111' })])
  })

  it('linkProvider is idempotent on the same (identityId, providerSub) pair', async () => {
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    const ident = await adapter.identities.find({ id: identityA })
    expect(ident?.providers).toHaveLength(1)
  })

  it('linkProvider refuses when the sub already belongs to another identity', async () => {
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    await expect(
      auth.flows.linkProvider({
        authorize: ALLOW_LINK,
        identityId: identityB,
        providerId: 'google',
        providerSub: 'google|111',
        session: null,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('linkProvider refuses a second account at a provider the identity already holds, and announces nothing', async () => {
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    const handler = vi.fn()
    auth.events.on('identity.linked', handler)

    await expect(
      auth.flows.linkProvider({
        authorize: ALLOW_LINK,
        identityId: identityA,
        providerId: 'google',
        providerSub: 'google|222',
        session: null,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_TAKEN' })
    expect(handler).not.toHaveBeenCalled()
    const ident = await adapter.identities.find({ id: identityA })
    expect(ident.providers.map((p) => p.providerSub)).toEqual(['google|111'])
  })

  it('linkProvider rejects unknown identity', async () => {
    await expect(
      auth.flows.linkProvider({
        authorize: ALLOW_LINK,
        identityId: 'does-not-exist',
        providerId: 'google',
        providerSub: 'google|111',
        session: null,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
  })

  it('unlinkProvider removes the link', async () => {
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    // Add a password credential so the lockout guard does not trip.
    await adapter.credentials.create(
      credentialInput({ identityId: identityA, kind: 'password', secret: 'hashedXYZ' }),
      {},
    )
    await auth.flows.unlinkProvider({ identityId: identityA, providerId: 'google', session: null })
    const ident = await adapter.identities.find({ id: identityA })
    expect(ident?.providers).toEqual([])
  })

  it('unlinkProvider refuses when removing would leave zero factors', async () => {
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    await expect(
      auth.flows.unlinkProvider({ identityId: identityA, providerId: 'google', session: null }),
    ).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('unlinkProvider with allowLockout:true bypasses the lockout guard', async () => {
    await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|111',
      session: null,
    })
    await auth.flows.unlinkProvider({
      identityId: identityA,
      providerId: 'google',
      allowLockout: true,
      session: null,
    })
    const ident = await adapter.identities.find({ id: identityA })
    expect(ident?.providers).toEqual([])
  })

  it('linkProvider links in the tenant it names, which alone finds the sub', async () => {
    const result = await auth.flows.linkProvider({
      authorize: ALLOW_LINK,
      identityId: identityA,
      providerId: 'google',
      providerSub: 'google|t',
      session: null,
      tenantId: 'tenant-a',
    })

    expect(result.identity.providers).toEqual([
      expect.objectContaining({ providerSub: 'google|t', tenantId: 'tenant-a' }),
    ])
    const login = { providerId: 'google', providerSub: 'google|t' }
    expect((await adapter.identities.find({ ...login, tenantId: 'tenant-a' })).id).toBe(identityA)
    await expect(adapter.identities.find({ ...login, tenantId: null })).rejects.toMatchObject({
      code: 'AUTH_IDENTITY_NOT_FOUND',
    })
  })

  it('linkProvider links a sub the identity holds in another tenant, rather than answering it as a repeat', async () => {
    const login = { providerId: 'google', providerSub: 'google|1' }
    await adapter.identities.link(identityA, { ...login, tenantId: 'tenant-b' })

    await auth.flows.linkProvider({
      ...login,
      authorize: ALLOW_LINK,
      identityId: identityA,
      session: null,
      tenantId: 'tenant-a',
    })

    expect((await adapter.identities.find({ ...login, tenantId: 'tenant-a' })).id).toBe(identityA)
  })

  it('linkProvider refuses a sub another identity holds in the tenant, and takes it in another', async () => {
    await adapter.identities.link(identityB, {
      providerId: 'google',
      providerSub: 'google|shared',
      tenantId: 'tenant-b',
    })
    const link = { authorize: ALLOW_LINK, identityId: identityA, providerId: 'google', providerSub: 'google|shared' }

    await expect(auth.flows.linkProvider({ ...link, session: null, tenantId: 'tenant-b' })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
    await expect(auth.flows.linkProvider({ ...link, session: null, tenantId: 'tenant-a' })).resolves.toMatchObject({
      identityId: identityA,
    })
  })

  it('unlinkProvider unlinks in the tenant it names, counting only the ways into that tenant', async () => {
    await adapter.identities.link(identityA, { providerId: 'google', providerSub: 'google|1', tenantId: 'tenant-a' })
    await adapter.identities.link(identityA, { providerId: 'github', providerSub: 'gh|1', tenantId: 'tenant-b' })
    const unlink = { identityId: identityA, providerId: 'google', session: null, tenantId: 'tenant-a' }

    // A link into tenant-b lets nobody into tenant-a.
    await expect(auth.flows.unlinkProvider(unlink)).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    await adapter.identities.link(identityA, { providerId: 'github', providerSub: 'gh|1', tenantId: 'tenant-a' })
    const { identity } = await auth.flows.unlinkProvider(unlink)
    expect(identity.providers.map((p) => `${p.providerId}@${p.tenantId}`).sort()).toEqual([
      'github@tenant-a',
      'github@tenant-b',
    ])
  })

  it('unlinkProvider is a no-op for a provider the identity holds only in another tenant', async () => {
    await adapter.identities.link(identityA, { providerId: 'google', providerSub: 'google|1', tenantId: 'tenant-b' })
    const handler = vi.fn()
    auth.events.on('identity.unlinked', handler)

    const { identity } = await auth.flows.unlinkProvider({
      identityId: identityA,
      providerId: 'google',
      session: null,
      tenantId: 'tenant-a',
    })

    expect(identity.providers).toEqual([expect.objectContaining({ providerId: 'google', tenantId: 'tenant-b' })])
    expect(handler).not.toHaveBeenCalled()
  })

  it('unlinkProvider is a no-op for a provider that was never linked', async () => {
    const result = await auth.flows.unlinkProvider({
      identityId: identityA,
      providerId: 'github',
      session: null,
    })
    expect(result).toMatchObject({ identityId: identityA, providerId: 'github' })
    // A no-op still answers with the identity, so a caller never has to branch
    // on "did anything change" to know what it now holds.
    expect(result.identity.id).toBe(identityA)
    expect(result.identity.providers.some((p) => p.providerId === 'github')).toBe(false)
  })
})
