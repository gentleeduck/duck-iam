/**
 * The registry is what turns a provider id from a request body into the code
 * that runs, and what `auth.passwords` / `auth.mfa` / `auth.apiKeys` resolve
 * through. Two things decide both: the id map and `resolve`'s instanceof scan.
 *
 * The existing suite covers duplicate ids and the instanceof lookup. These cover
 * what an id may be, what happens when two capabilities answer the same
 * instanceof question, and the disagreement between what `list()` advertises and
 * what `begin` will actually accept.
 */
import { describe, expect, it } from 'vitest'
import { Providers } from '../provider'
import type { Provider } from '../provider.types'

/** A capability with exactly the members the test names, and nothing else. */
function cap(id: string, over: Partial<Provider.Capability> = {}): Provider.Capability {
  return { id, kind: 'test', ...over } as Provider.Capability
}

const signIn = (id: string): Provider.Capability =>
  cap(id, { begin: async () => [], complete: async () => [] } as never)

/** A capability that signs nobody in, shaped the way every shipped one is: a class instance. */
class Facet {
  readonly kind = 'test'
  constructor(readonly id: string) {}
}

const facet = (id: string): Provider.Capability => new Facet(id) as Provider.Capability

const misconfigured = expect.objectContaining({ code: 'AUTH_MISCONFIGURED' })
const ctx = {} as Provider.Context

describe('what an id may be', () => {
  it('refuses a second capability claiming a taken id', () => {
    const registry = new Providers([signIn('password')])
    expect(() => registry.register(signIn('password'))).toThrow(misconfigured)
  })

  it('refuses an empty id, which is what an unfilled config field leaves behind', () => {
    expect(() => new Providers([signIn('')])).toThrow(misconfigured)
  })

  it('refuses an id carrying anything that would not survive a log line or a URL', () => {
    const ids = [
      '<script>alert(1)</script>',
      'has space',
      `nul${String.fromCharCode(0)}byte`,
      'x'.repeat(129),
      '-leading',
    ]
    for (const id of ids) {
      expect(() => new Providers([signIn(id)])).toThrow(misconfigured)
    }
  })

  it('refuses a prototype-shaped id, which a caller keying its own object by provider id would inherit', () => {
    for (const id of ['__proto__', 'constructor', 'prototype', 'ConStructor']) {
      expect(() => new Providers([signIn(id)])).toThrow(misconfigured)
    }
  })

  it('matches an id case-insensitively, so the case a request arrived in cannot decide the answer', () => {
    const registry = new Providers([signIn('Password')])
    expect(registry.has('PASSWORD')).toBe(true)
    expect(registry.get('password').id).toBe('Password')
    expect(registry.list()).toEqual([{ id: 'Password', kind: 'test' }])
    expect(() => registry.register(signIn('password'))).toThrow(misconfigured)
  })

  it('does not echo an unregistrable id back inside the error it raises', () => {
    // The id comes from the request, so what lands in `meta.providerId` and survives the wire-safe
    // envelope has to be an id that could have been registered, not whatever a client sent.
    const registry = new Providers()
    const err = (() => {
      try {
        registry.get('<script>alert(1)</script>')
      } catch (e) {
        return e as { toJSON(): { error: Record<string, unknown> } }
      }
    })()
    expect(err?.toJSON().error).toMatchObject({ providerId: 'invalid' })
  })

  it('registers a whole list or none of it', () => {
    // `Providers` has no unregister, so the two that landed before the collision would have stayed
    // for the life of the engine, under a plugin that failed to install.
    const registry = new Providers([signIn('kept')])
    expect(() => registry.registerAll([signIn('a'), signIn('b'), signIn('a')])).toThrow(misconfigured)
    expect(registry.list().map((p) => p.id)).toEqual(['kept'])
  })

  it('has no way to remove a capability once registered', () => {
    // Pinned because `register` is public for plugins: what a plugin adds at
    // runtime stays for the life of the engine.
    const registry = new Providers([signIn('a')])
    expect('unregister' in registry).toBe(false)
  })
})

describe('what list advertises against what begin accepts', () => {
  it('leaves out a capability that cannot complete a sign-in', () => {
    const registry = new Providers([facet('mfa'), signIn('password')])
    expect(registry.list().map((p) => p.id)).toEqual(['password'])
  })

  it('refuses a capability holding one half of a sign-in, rather than advertising one that cannot begin', () => {
    // A class instance on purpose: a plain object with neither half is refused for being unreachable
    // instead, which would let this pass without the begin/complete rule being there at all.
    class HalfFacet {
      readonly id = 'half'
      readonly kind = 'test'
      async complete(): Promise<Provider.InternalIntent[]> {
        return []
      }
    }
    class OtherHalfFacet {
      readonly id = 'other-half'
      readonly kind = 'test'
      async begin(): Promise<Provider.Intent[]> {
        return []
      }
    }
    expect(() => new Providers([new HalfFacet() as never])).toThrow(misconfigured)
    expect(() => new Providers([new OtherHalfFacet() as never])).toThrow(misconfigured)
  })

  it('refuses a capability nothing can reach: no begin, no complete, and no prototype to resolve by', () => {
    expect(() => new Providers([{ ...new Facet('copy') } as never])).toThrow(misconfigured)
  })

  it('separates an unknown provider from one that signs nobody in', async () => {
    const registry = new Providers([facet('attach-only')])
    const codeOf = async (id: string): Promise<string | undefined> =>
      registry
        .begin(id, ctx, {})
        .then(() => undefined)
        .catch((e: { code: string }) => e.code)

    expect(await codeOf('nonexistent')).toBe('AUTH_PROVIDER_FAILED')
    expect(await codeOf('attach-only')).toBe('AUTH_PROVIDER_UNSUPPORTED')
  })

  it('dispatches begin and complete to the registered instance with this still bound', async () => {
    class Stateful {
      readonly id = 'stateful'
      readonly kind = 'test'
      private readonly _marker = 'kept'
      async begin(): Promise<Provider.Intent[]> {
        return [{ body: { marker: this._marker }, status: 200, type: 'json' }]
      }
      async complete(): Promise<Provider.InternalIntent[]> {
        return []
      }
    }
    const registry = new Providers([new Stateful() as never])
    expect(await registry.begin('stateful', ctx, {})).toEqual([{ body: { marker: 'kept' }, status: 200, type: 'json' }])
  })

  it('hands the input to the provider unexamined', async () => {
    // Deliberate, since only the provider knows its own shape, and pinned so it stays a decision:
    // the registry is not a validation boundary, so whatever the body deserialised to arrives as-is.
    const seen: unknown[] = []
    const registry = new Providers([
      cap('echo', {
        begin: async (_c: unknown, input: unknown) => {
          seen.push(input)
          return []
        },
        complete: async () => [],
      } as never),
    ])
    const hostile = { __proto__: { polluted: true }, toString: 1 }
    await registry.begin('echo', ctx, hostile)
    expect(seen[0]).toBe(hostile)
  })
})

describe('resolving a facet by its class', () => {
  class Base {
    readonly id = 'base'
    readonly kind = 'test'
  }
  class Subclass extends Base {
    override readonly id = 'subclass' as never
  }

  it('returns the entry that is an instance of the constructor', () => {
    const instance = new Base()
    expect(new Providers([instance as never]).resolve(Base)).toBe(instance)
  })

  it('returns null when nothing matches', () => {
    expect(new Providers([signIn('a')]).resolve(Base)).toBeNull()
  })

  it('refuses a resolve a subclass and its base both answer, rather than letting registration order pick', () => {
    // A plugin that subclasses a shipped facet would otherwise decide what `auth.passwords`,
    // `auth.mfa` and `auth.apiKeys` return by registering first, without ever colliding on an id.
    const registry = new Providers([new Subclass() as never, new Base() as never])
    expect(() => registry.resolve(Base)).toThrow(misconfigured)
  })

  it('refuses an ambiguous resolve rather than reporting the first match', () => {
    const registry = new Providers([new Base() as never, Object.assign(new Base(), { id: 'base-2' }) as never])
    expect(() => registry.resolve(Base)).toThrow(misconfigured)
  })

  it('a base instance does not answer a resolve for the subclass', () => {
    expect(new Providers([new Base() as never]).resolve(Subclass)).toBeNull()
  })

  it('still resolves the subclass on its own', () => {
    const only = new Subclass()
    expect(new Providers([only as never]).resolve(Base)).toBe(only)
  })
})
