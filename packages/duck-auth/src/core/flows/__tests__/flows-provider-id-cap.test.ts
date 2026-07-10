import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function buildAuth(): AuthEngine<MyProfile> {
  const adapter = new MemoryAdapter<MyProfile>()
  return new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
  })
}

describe('FlowsImpl provider id reflection-DoS defense', () => {
  it('signIn refuses an oversize providerId without echoing it back in meta', async () => {
    const auth = buildAuth()
    const huge = 'x'.repeat(129)
    try {
      await auth.flows.signIn({ providerId: huge, input: {} })
      throw new Error('expected AUTH/PROVIDER_FAILED')
    } catch (err) {
      const e = err as { code?: string; meta?: { providerId?: string } }
      expect(e.code).toBe('AUTH_PROVIDER_FAILED')
      expect(e.meta?.providerId).toBe('invalid')
    }
  })

  it('signIn still echoes a normal-length unknown providerId for legitimate debugging', async () => {
    const auth = buildAuth()
    try {
      await auth.flows.signIn({ providerId: 'nope', input: {} })
      throw new Error('expected AUTH/PROVIDER_FAILED')
    } catch (err) {
      const e = err as { code?: string; meta?: { providerId?: string } }
      expect(e.code).toBe('AUTH_PROVIDER_FAILED')
      expect(e.meta?.providerId).toBe('nope')
    }
  })

  it('beginProvider refuses an oversize providerId without echoing it back', async () => {
    const auth = buildAuth()
    const huge = 'y'.repeat(200)
    try {
      await auth.flows.beginProvider(huge, {})
      throw new Error('expected AUTH/PROVIDER_FAILED')
    } catch (err) {
      const e = err as { code?: string; meta?: { providerId?: string } }
      expect(e.code).toBe('AUTH_PROVIDER_FAILED')
      expect(e.meta?.providerId).toBe('invalid')
    }
  })

  it('beginProvider rejects non-string providerId (typeof guard)', async () => {
    const auth = buildAuth()
    try {
      await auth.flows.beginProvider(42 as unknown as string, {})
      throw new Error('expected AUTH/PROVIDER_FAILED')
    } catch (err) {
      const e = err as { code?: string; meta?: { providerId?: string } }
      expect(e.code).toBe('AUTH_PROVIDER_FAILED')
      expect(e.meta?.providerId).toBe('invalid')
    }
  })
})
