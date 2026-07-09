import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config/config'
import { ApiKeysFacet } from '~/providers/api-key/api-key.facet'
import { apiKeyProvider } from '~/providers/api-key/api-key.provider'
import { MfaFacet } from '~/providers/mfa/mfa.facet'
import { mfaProvider } from '~/providers/mfa/mfa.provider'

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
})
