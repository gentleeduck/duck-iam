import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { CookieTransport } from '../../transport/cookie'
import type { Engine } from '../engine.types'
import { AuthEngine } from '../engine'

function baseConfig(): Engine.Config {
  const a = new MemoryAdapter()
  return {
    baseUrl: 'https://x.test',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: { identities: a.identities, sessions: a.sessions, credentials: a.credentials },
  }
}

describe('provider registry', () => {
  it('engine builds with providers: [] (no throw at construction)', () => {
    expect(() => new AuthEngine({ ...baseConfig(), providers: [] })).not.toThrow()
  })

  // Target behavior lands in Task 2, when password is no longer eager-built.
  // In Task 1 the engine still eager-builds passwords, so this stays skipped.
  it.skip('accessing an unregistered capability throws AUTH_PROVIDER_NOT_REGISTERED', () => {
    const auth = new AuthEngine({ ...baseConfig(), providers: [] })
    expect(() => auth.passwords).toThrow(/AUTH_PROVIDER_NOT_REGISTERED|password/)
  })
})
