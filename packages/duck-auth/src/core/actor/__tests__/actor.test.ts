import { afterEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId, currentActor, resolveActor, setDefaultActorResolver, withActor } from '../actor'

afterEach(() => setDefaultActorResolver(undefined))

describe('actor context', () => {
  it('resolves explicit over ambient over configured default', () => {
    setDefaultActorResolver(() => 'from-config')
    expect(actorId()).toBe('from-config')

    withActor('from-ambient', () => {
      // Ambient beats config: a request that named its actor is more specific
      // than a process-wide fallback.
      expect(actorId()).toBe('from-ambient')
      // Explicit beats both, which is what lets one call be attributed to an
      // operator acting on someone else's row.
      expect(actorId({ actorId: 'explicit' })).toBe('explicit')
    })
  })

  it('records null rather than inventing a placeholder when nothing is bound', () => {
    expect(actorId()).toBeNull()
    expect(currentActor()).toBeUndefined()
    expect(resolveActor()).toEqual({})
  })

  it('a resolver returning null or undefined means no actor, not a broken one', () => {
    setDefaultActorResolver(() => null)
    expect(actorId()).toBeNull()
    setDefaultActorResolver(() => undefined)
    expect(actorId()).toBeNull()
  })

  it('withActor(undefined) is a fence that clears the scope', async () => {
    await withActor('outer', async () => {
      // Matches `withTenant`. `erase` relies on this being a deliberate clear,
      // which is why it binds only when it actually has an operator id.
      await withActor(undefined, async () => {
        expect(actorId()).toBeNull()
      })
      expect(actorId()).toBe('outer')
    })
  })

  it('the configured default reaches a real store write', async () => {
    setDefaultActorResolver(() => 'svc-provisioner')
    const store = new MemoryAdapter().identities

    // The point of the config hook: provenance without wrapping every call.
    const i = await store.create({ emailVerified: false, profile: { email: 'a@x', username: 'a' }, providers: [] })
    expect(i.createdBy).toBe('svc-provisioner')
  })
})
