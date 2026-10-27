import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config/config'
import { authTestDataAtRest } from '~/test'
import { MfaImpl, mfa } from '../mfa'
import type { Mfa } from '../mfa.types'

function auth(cfg: Mfa.CfgInput) {
  const a = new MemoryAdapter()
  return createAuth({
    baseUrl: 'https://x.test',
    stores: { identities: a.identities, sessions: a.sessions, credentials: a.credentials },
    providers: [mfa(cfg)],
  })
}

describe('mfaProvider thunk', () => {
  it('mounts an MfaFacet resolvable via auth.mfa', () => {
    expect(auth({ dataAtRest: authTestDataAtRest() }).mfa).toBeInstanceOf(MfaImpl)
  })

  it('refuses to boot without a key, not at the first enrollment', () => {
    const noKey: Mfa.CfgInput = Object.assign({ dataAtRest: authTestDataAtRest() }, { dataAtRest: undefined })
    expect(() => auth(noKey)).toThrow('AUTH_MISCONFIGURED')
  })
})
