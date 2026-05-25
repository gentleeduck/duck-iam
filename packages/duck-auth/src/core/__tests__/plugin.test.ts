import { describe, expect, it, vi } from 'vitest'
import { MemoryAuthAdapter } from '../../adapters/memory'
import { MemoryLimiter } from '../../limiters/memory'
import { AuthRoot } from '../auth'
import { CookieTransport } from '../transport/cookie'

describe('Plugin system', () => {
  function buildAuth() {
    const adapter = new MemoryAuthAdapter()
    return new AuthRoot({
      baseUrl: 'https://x',
      transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
      stores: {
        identities: adapter.identities,
        sessions: adapter.sessions,
        credentials: adapter.credentials,
      },
      limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    })
  }

  it('install runs the install hook + registers providers + wires events + exposes facet', async () => {
    const auth = buildAuth()
    const onInstall = vi.fn()
    const onLockout = vi.fn()

    const fakeProvider = {
      id: 'fake-provider',
      kind: 'password' as const,
      async begin() {
        return []
      },
      async complete() {
        return []
      },
    }

    await auth.use({
      id: 'demo',
      install: onInstall,
      providers: [fakeProvider],
      events: { lockout: onLockout },
      facet: { ping: () => 'pong' },
    })

    expect(onInstall).toHaveBeenCalledWith(auth)
    expect(auth.providers.has('fake-provider')).toBe(true)
    expect(auth.plugins.installed.has('demo')).toBe(true)
    expect((auth.plugins.facets.demo as { ping: () => string }).ping()).toBe('pong')

    // Event subscription is live.
    await auth.events.emit('lockout', { identityId: 'u', until: Date.now() + 1000 })
    expect(onLockout).toHaveBeenCalledOnce()
  })

  it('refuses to install the same plugin id twice', async () => {
    const auth = buildAuth()
    await auth.use({ id: 'demo' })
    await expect(auth.use({ id: 'demo' })).rejects.toThrow(/already installed/)
  })

  it('install without a duplicate provider id (atomic when the registration succeeds)', async () => {
    const auth = buildAuth()
    const p = {
      id: 'p1',
      kind: 'password' as const,
      async begin() {
        return []
      },
      async complete() {
        return []
      },
    }
    await auth.use({ id: 'demo', providers: [p] })
    // Re-using provider id from a different plugin id surfaces via providers facet.
    await expect(auth.use({ id: 'demo2', providers: [p] })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })

  it('plugins.dispose() unhooks every event subscription wired by install', async () => {
    const auth = buildAuth()
    const handler = vi.fn()
    await auth.use({ id: 'demo', events: { lockout: handler } })
    auth.plugins.dispose()
    await auth.events.emit('lockout', { identityId: 'u', until: 0 })
    expect(handler).not.toHaveBeenCalled()
  })
})
