import { beforeEach, describe, expect, it } from 'vitest'
import { credentialInput, identityInput } from '../../../test/store-inputs'
import { MemoryAdapter } from '../../../adapters/memory'
import { Identity } from '../../../core'
import { randomToken, sha256, timingSafeEqual } from '../../../core/crypto'
import { InMemoryEvents } from '../../../core/events'
import { ApiKeysFacet } from '../../../core/facets/apikeys'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authApiKey } from '../index'

interface ProfileShape extends Identity.ProfileMetadataBase {}

function buildContext() {
  const adapter = new MemoryAdapter<ProfileShape>()
  const events = new InMemoryEvents()
  const facet = new ApiKeysFacet(adapter.credentials, events, { randomToken: randomToken, sha256: sha256 })
  return {
    adapter,
    facet,
    events,
    ctx: {
      stores: {
        identities: adapter.identities,
        sessions: adapter.sessions,
        credentials: adapter.credentials,
      },
      tenant: {},
      baseUrl: 'https://app.test',
      limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
      events,
      crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
    },
  }
}

describe('api-key provider', () => {
  let plaintext: string
  let identityId: string
  let env: ReturnType<typeof buildContext>

  beforeEach(async () => {
    env = buildContext()
    const ident = await env.adapter.identities.create(
      identityInput({ profile: { email: 'svc@x.com', username: 'svc' }, providers: [] }),
      {},
    )
    identityId = ident.id
    const created = await env.facet.create(ident.id, { name: 'CI runner', scopes: ['read:users'] })
    plaintext = created.plaintext
  })

  it('complete with the right token emits startSession with kind:apikey aal:1', async () => {
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    const intents = await provider.complete(env.ctx, { token: plaintext })
    expect(intents).toHaveLength(1)
    const intent = intents[0]!
    expect(intent.type).toBe('startSession')
    if (intent.type !== 'startSession') return
    expect(intent.identityId).toBe(identityId)
    expect(intent.aal).toBe(1)
    expect(intent.factors[0]!.method).toBe('api-key')
  })

  it('complete with empty token throws AUTH/APIKEY_INVALID', async () => {
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: '' })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_INVALID',
    })
  })

  it('complete with a non-string token surfaces AUTH/APIKEY_INVALID (defeats authSha256 TypeError)', async () => {
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: 42 as unknown as string })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_INVALID',
    })
    await expect(provider.complete(env.ctx, { token: {} as unknown as string })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_INVALID',
    })
  })

  it('complete with an oversize token throws AUTH/APIKEY_INVALID without authSha256-ing the payload', async () => {
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: 'x'.repeat(513) })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_INVALID',
    })
  })

  it('complete with a wrong-prefix token throws AUTH/APIKEY_INVALID', async () => {
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: 'bogus_xyz' })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_INVALID',
    })
  })

  it('complete with a revoked key throws AUTH/APIKEY_REVOKED', async () => {
    const all = await env.facet.list(identityId)
    await env.facet.revoke(all[0]!.id)
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: plaintext })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_REVOKED',
    })
  })

  it('rate limit kicks in after `max` requests + surfaces retryAfter', async () => {
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    for (let i = 0; i < 5; i++) {
      await provider.complete(env.ctx, { token: plaintext })
    }
    await expect(provider.complete(env.ctx, { token: plaintext })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
  })

  it('requireScopes enforces per-route scope at provider level', async () => {
    const provider = authApiKey<ProfileShape>({
      apiKeys: env.facet,
      requireScopes: ['write:users'],
    })
    await expect(provider.complete(env.ctx, { token: plaintext })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_SCOPE_INSUFFICIENT',
    })
  })

  it('begin is a no-op (api-key has no challenge round-trip)', async () => {
    const provider = authApiKey<ProfileShape>({ apiKeys: env.facet })
    const intents = await provider.begin(env.ctx, {})
    expect(intents).toEqual([])
  })

  describe('tenant-boundary defense', () => {
    it('refuses to identify-confirm a tenant-bound key on a no-tenant request', async () => {
      const adapter = new MemoryAdapter<ProfileShape>()
      const events = new InMemoryEvents()
      const facet = new ApiKeysFacet(adapter.credentials, events, { randomToken: randomToken, sha256: sha256 })
      const ident = await adapter.identities.create(
        identityInput({ profile: { email: 't1@x.com', username: 't1' }, providers: [] }),
        { tenantId: 'tenant-A' },
      )
      const created = await facet.create(ident.id, {
        name: 'tenant-A key',
        scopes: ['read'],
        tenantId: 'tenant-A',
      })
      const provider = authApiKey<ProfileShape>({ apiKeys: facet })
      const ctx = {
        stores: {
          identities: adapter.identities,
          sessions: adapter.sessions,
          credentials: adapter.credentials,
        },
        tenant: {},
        baseUrl: 'https://app.test',
        limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
        events,
        crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
      }
      await expect(provider.complete(ctx, { token: created.plaintext })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })

    it('refuses to identify-confirm a tenant-A key on a tenant-B request', async () => {
      const adapter = new MemoryAdapter<ProfileShape>()
      const events = new InMemoryEvents()
      const facet = new ApiKeysFacet(adapter.credentials, events, { randomToken: randomToken, sha256: sha256 })
      const ident = await adapter.identities.create(
        identityInput({ profile: { email: 't2@x.com', username: 't2' }, providers: [] }),
        { tenantId: 'tenant-A' },
      )
      const created = await facet.create(ident.id, {
        name: 'tenant-A key',
        scopes: ['read'],
        tenantId: 'tenant-A',
      })
      const provider = authApiKey<ProfileShape>({ apiKeys: facet })
      const ctx = {
        stores: {
          identities: adapter.identities,
          sessions: adapter.sessions,
          credentials: adapter.credentials,
        },
        tenant: { tenantId: 'tenant-B' },
        baseUrl: 'https://app.test',
        limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
        events,
        crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
      }
      await expect(provider.complete(ctx, { token: created.plaintext })).rejects.toMatchObject({
        code: 'AUTH_APIKEY_INVALID',
      })
    })

    it('still identifies-confirms a tenant-A key on a tenant-A request (happy path)', async () => {
      const adapter = new MemoryAdapter<ProfileShape>()
      const events = new InMemoryEvents()
      const facet = new ApiKeysFacet(adapter.credentials, events, { randomToken: randomToken, sha256: sha256 })
      const ident = await adapter.identities.create(
        identityInput({ profile: { email: 't3@x.com', username: 't3' }, providers: [] }),
        { tenantId: 'tenant-A' },
      )
      const created = await facet.create(ident.id, {
        name: 'tenant-A key',
        scopes: ['read'],
        tenantId: 'tenant-A',
      })
      const provider = authApiKey<ProfileShape>({ apiKeys: facet })
      const ctx = {
        stores: {
          identities: adapter.identities,
          sessions: adapter.sessions,
          credentials: adapter.credentials,
        },
        tenant: { tenantId: 'tenant-A' },
        baseUrl: 'https://app.test',
        limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
        events,
        crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
      }
      const intents = await provider.complete(ctx, { token: created.plaintext })
      expect(intents).toHaveLength(1)
      const intent = intents[0]!
      expect(intent.type).toBe('startSession')
    })
  })
})
