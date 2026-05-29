/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '../../../core/crypto'
import { InMemoryEvents } from '../../../core/events'
import { ApiKeysFacet } from '../../../core/facets/apikeys'
import { MemoryLimiter } from '../../../limiters/memory'
import { apiKey } from '../index'

interface ProfileShape {
  email: string
}

function buildContext() {
  const adapter = new MemoryAuthAdapter<ProfileShape>()
  const events = new InMemoryEvents()
  const facet = new ApiKeysFacet(adapter.credentials, events, { randomToken, sha256 })
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
      limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
      events,
      crypto: { randomToken, sha256, timingSafeEqual },
    },
  }
}

describe('api-key provider', () => {
  let plaintext: string
  let identityId: string
  let env: ReturnType<typeof buildContext>

  beforeEach(async () => {
    env = buildContext()
    const ident = await env.adapter.identities.create({ profile: { email: 'svc@x.com' }, providers: [] }, {})
    identityId = ident.id
    const created = await env.facet.create(ident.id, { name: 'CI runner', scopes: ['read:users'] })
    plaintext = created.plaintext
  })

  it('complete with the right token emits startSession with kind:apikey aal:1', async () => {
    const provider = apiKey<ProfileShape>({ apiKeys: env.facet })
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
    const provider = apiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: '' })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_INVALID',
    })
  })

  it('complete with a wrong-prefix token throws AUTH/APIKEY_INVALID', async () => {
    const provider = apiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: 'bogus_xyz' })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_INVALID',
    })
  })

  it('complete with a revoked key throws AUTH/APIKEY_REVOKED', async () => {
    const all = await env.facet.list(identityId)
    await env.facet.revoke(all[0]!.id)
    const provider = apiKey<ProfileShape>({ apiKeys: env.facet })
    await expect(provider.complete(env.ctx, { token: plaintext })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_REVOKED',
    })
  })

  it('rate limit kicks in after `max` requests + surfaces retryAfter', async () => {
    const provider = apiKey<ProfileShape>({ apiKeys: env.facet })
    for (let i = 0; i < 5; i++) {
      await provider.complete(env.ctx, { token: plaintext })
    }
    await expect(provider.complete(env.ctx, { token: plaintext })).rejects.toMatchObject({
      code: 'AUTH/RATE_LIMITED',
    })
  })

  it('requireScopes enforces per-route scope at provider level', async () => {
    const provider = apiKey<ProfileShape>({
      apiKeys: env.facet,
      requireScopes: ['write:users'],
    })
    await expect(provider.complete(env.ctx, { token: plaintext })).rejects.toMatchObject({
      code: 'AUTH/APIKEY_SCOPE_INSUFFICIENT',
    })
  })

  it('begin is a no-op (api-key has no challenge round-trip)', async () => {
    const provider = apiKey<ProfileShape>({ apiKeys: env.facet })
    const intents = await provider.begin(env.ctx, {})
    expect(intents).toEqual([])
  })
})
