import { afterEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { actorId, setDefaultActorResolver, withActor } from '../actor'

afterEach(() => setDefaultActorResolver(undefined))

describe('actor context', () => {
  it('answers the ambient scope over the configured default', () => {
    setDefaultActorResolver(() => 'from-config')
    expect(actorId()).toBe('from-config')
    withActor('from-ambient', () => {
      expect(actorId()).toBe('from-ambient')
    })
  })

  it('records null rather than inventing a placeholder when nothing is bound', () => {
    expect(actorId()).toBeNull()
  })

  it.each([null, undefined, ''])('a resolver answering %j means no actor, not a broken one', (answer) => {
    setDefaultActorResolver(() => answer)
    expect(actorId()).toBeNull()
  })

  it.each([undefined, ''])('withActor(%j) is a fence that clears the scope across awaits', async (none) => {
    await withActor('outer', async () => {
      await withActor(none, async () => {
        await Promise.resolve()
        expect(actorId()).toBeNull()
      })
      expect(actorId()).toBe('outer')
    })
  })

  it('a fence clears the scope, not the configured default', async () => {
    setDefaultActorResolver(() => 'from-config')
    await withActor('outer', () => withActor(undefined, async () => expect(actorId()).toBe('from-config')))
  })

  it('a resolver that throws is raised, and never asked while a scope is bound', () => {
    setDefaultActorResolver(() => {
      throw new Error('actor lookup down')
    })
    expect(() => actorId()).toThrow('actor lookup down')
    withActor('bound', () => expect(actorId()).toBe('bound'))
  })

  it('the configured default reaches a real store write', async () => {
    setDefaultActorResolver(() => 'svc-provisioner')
    const store = new MemoryAdapter().identities

    const i = await store.create({ emailVerified: false, profile: { email: 'a@x', username: 'a' }, providers: [] })
    expect(i.createdBy).toBe('svc-provisioner')
  })
})
