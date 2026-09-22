import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { AuthEngine } from '../engine'
import type { Engine } from '../engine.types'

function baseCfg(): Engine.Cfg {
  const a = new MemoryAdapter()
  return {
    baseUrl: 'https://x.test',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: { identities: a.identities, sessions: a.sessions, credentials: a.credentials },
  }
}

describe('provider registry', () => {
  it('engine builds with providers: [] (no throw at construction)', () => {
    expect(() => new AuthEngine({ ...baseCfg(), providers: [] })).not.toThrow()
  })

  it('accessing an unregistered capability throws AUTH_PROVIDER_NOT_REGISTERED', () => {
    const auth = new AuthEngine({ ...baseCfg(), providers: [] })
    expect(() => auth.passwords).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|password/)
  })
})
