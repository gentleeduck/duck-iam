import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import { ApiKeysFacet } from '~/providers/api-key/api-key.facet'
import { MfaFacet } from '../mfa.facet'

describe('facet registry identity', () => {
  it('MfaFacet advertises id/kind', () => {
    const f = new MfaFacet(new MemoryAdapter().credentials, new InMemoryEvents())
    expect(f.id).toBe('mfa')
    expect(f.kind).toBe('mfa')
  })

  it('ApiKeysFacet advertises id/kind (facet id distinct from sign-in provider)', () => {
    const f = new ApiKeysFacet(new MemoryAdapter().credentials, new InMemoryEvents(), { randomToken, sha256 })
    expect(f.id).toBe('api-keys')
    expect(f.kind).toBe('api-key')
  })
})
