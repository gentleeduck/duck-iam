import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config/config'
import type { AuthError } from '~/core/errors'
import { OrgsImpl } from '~/core/orgs'
import { ApiKeysFacet, apiKeyProvider } from '~/providers/api-key'
import { MfaFacet, mfaProvider } from '~/providers/mfa'

function base() {
  const a = new MemoryAdapter()
  return {
    baseUrl: 'https://x.test',
    stores: { identities: a.identities, sessions: a.sessions, credentials: a.credentials },
  }
}

describe('engine capability getters', () => {
  it('resolves mfa + apiKeys facets by type', () => {
    const auth = createAuth({ ...base(), providers: [mfaProvider(), apiKeyProvider()] })
    expect(auth.mfa).toBeInstanceOf(MfaFacet)
    expect(auth.apiKeys).toBeInstanceOf(ApiKeysFacet)
  })

  it('throws AUTH_PROVIDER_NOT_REGISTERED when a capability is absent', () => {
    const auth = createAuth({ ...base(), providers: [] })
    expect(() => auth.mfa).toThrow(/AUTH_PROVIDER_NOT_REGISTERED/)
  })

  it('throws AUTH_PROVIDER_NOT_REGISTERED when no org store was configured', () => {
    const auth = createAuth({ ...base(), providers: [] })
    expect(() => auth.orgs).toThrow(/AUTH_PROVIDER_NOT_REGISTERED/)
  })

  it('names the org store rather than a provider that does not exist', () => {
    const auth = createAuth({ ...base(), providers: [] })
    try {
      void auth.orgs
      expect.unreachable('orgs should have thrown')
    } catch (err) {
      // There is no `orgsProvider()`; the capability comes off `stores.orgs`. `message` is the code, so the
      // text an operator reads is on `meta.detail` - which is why `toThrow(/AUTH_.../)` above proves nothing
      // about the wording.
      expect((err as AuthError).meta.detail).toMatch(/stores\.orgs/)
    }
  })

  it('answers the facet when an org store is configured', () => {
    const a = new MemoryAdapter()
    const auth = createAuth({ ...base(), stores: { ...base().stores, orgs: a.orgs } })
    expect(auth.orgs).toBeInstanceOf(OrgsImpl)
  })
})
