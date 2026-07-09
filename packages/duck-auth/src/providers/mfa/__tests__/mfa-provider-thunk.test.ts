import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config/config'
import { MfaFacet, mfaProvider } from '../mfa'

function auth() {
  const a = new MemoryAdapter()
  return createAuth({
    baseUrl: 'https://x.test',
    stores: { identities: a.identities, sessions: a.sessions, credentials: a.credentials },
    providers: [mfaProvider()],
  })
}

describe('mfaProvider thunk', () => {
  it('mounts an MfaFacet resolvable via auth.mfa', () => {
    expect(auth().mfa).toBeInstanceOf(MfaFacet)
  })
})
