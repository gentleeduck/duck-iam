import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config/config'
import { OrgsImpl } from '~/core/orgs'
import { ApiKeysFacet, apiKeyProvider } from '~/providers/api-key'
import { MfaFacet, mfaProvider } from '~/providers/mfa'
import { PasskeyImpl, passkey } from '~/providers/passkey'

function base() {
  const a = new MemoryAdapter()
  return {
    baseUrl: 'https://x.test',
    stores: { identities: a.identities, sessions: a.sessions, credentials: a.credentials },
  }
}

type Facets = {
  readonly passwords: unknown
  readonly passkeys: unknown
  readonly mfa: unknown
  readonly apiKeys: unknown
}

describe('engine capability getters', () => {
  it('resolves mfa + apiKeys facets by type', () => {
    const auth = createAuth({ ...base(), providers: [mfaProvider(), apiKeyProvider()] })
    expect(auth.mfa).toBeInstanceOf(MfaFacet)
    expect(auth.apiKeys).toBeInstanceOf(ApiKeysFacet)
  })

  it('answers the registered passkey provider as the passkeys facet, on the engine and in a transaction', () => {
    const stores = base().stores
    const provider = passkey({
      rpID: 'x.test',
      rpName: 'X',
      expectedOrigins: ['https://x.test'],
      findIdentityByEmail: async () => null,
    })
    const auth = createAuth({ ...base(), providers: [provider], stores: { ...stores, withClient: () => stores } })
    expect(auth.passkeys).toBeInstanceOf(PasskeyImpl)
    expect(auth.passkeys).toBe(provider)
    expect(auth.withTransaction({}).passkeys).toBe(provider)
  })

  it('throws AUTH_PROVIDER_NOT_REGISTERED when a capability is absent', () => {
    const auth = createAuth({ ...base(), providers: [] })
    expect(() => auth.mfa).toThrow(/AUTH_PROVIDER_NOT_REGISTERED/)
  })

  it('throws AUTH_PROVIDER_NOT_REGISTERED when no org store was configured', () => {
    const auth = createAuth({ ...base(), providers: [] })
    expect(() => auth.orgs).toThrow(/AUTH_PROVIDER_NOT_REGISTERED/)
  })

  // `message` is the code, so the text an operator reads is on `meta.detail`, which `toThrow(/AUTH_.../)`
  // above says nothing about.
  it('names the org store rather than a provider that does not exist', () => {
    const auth = createAuth({ ...base(), providers: [] })
    expect(() => auth.orgs).toThrowError(
      expect.objectContaining({ meta: { detail: expect.stringMatching(/stores\.orgs/) } }),
    )
  })

  it.each([
    { factory: 'passwords()', id: 'password', read: (auth: Facets) => auth.passwords },
    { factory: 'passkey()', id: 'passkey', read: (auth: Facets) => auth.passkeys },
    { factory: 'mfaProvider()', id: 'mfa', read: (auth: Facets) => auth.mfa },
    { factory: 'apiKeyProvider()', id: 'api-key', read: (auth: Facets) => auth.apiKeys },
  ])('names $factory, the factory of the $id provider, on the engine and in a transaction', ({ factory, id, read }) => {
    const stores = base().stores
    const auth = createAuth({ ...base(), providers: [], stores: { ...stores, withClient: () => stores } })
    const refusal = expect.objectContaining({
      code: 'AUTH_PROVIDER_NOT_REGISTERED',
      meta: { detail: `this operation needs the '${id}' provider; add ${factory} to providers[]` },
    })
    expect(() => read(auth)).toThrowError(refusal)
    expect(() => read(auth.withTransaction({}))).toThrowError(refusal)
  })

  it('answers the facet when an org store is configured', () => {
    const a = new MemoryAdapter()
    const auth = createAuth({ ...base(), stores: { ...base().stores, orgs: a.orgs } })
    expect(auth.orgs).toBeInstanceOf(OrgsImpl)
  })
})
