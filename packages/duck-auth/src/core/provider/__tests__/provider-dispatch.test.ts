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

const ctx = {} as Provider.Context

describe('what an id may be', () => {
  it('refuses a second capability claiming a taken id', () => {
    const registry = new Providers([signIn('password')])
    expect(() => registry.register(signIn('password'))).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('FINDING: an empty id is a valid id', () => {
    // Nothing validates the string. An empty id registers, answers `has('')`, and
    // is dispatchable, so a capability built from a config where the id was never
    // filled in is silently reachable rather than refused at boot.
    const registry = new Providers([signIn('')])
    expect(registry.has('')).toBe(true)
    expect(registry.list()).toEqual([{ id: '', kind: 'test' }])
  })

  it('FINDING: a prototype-shaped id registers and dispatches like any other', () => {
    // Safe here because the store is a Map rather than an object literal, but the
    // id reaches the caller's own routing and logging untouched.
    const registry = new Providers([signIn('__proto__'), signIn('constructor')])
    expect(registry.has('__proto__')).toBe(true)
    expect(registry.get('constructor').id).toBe('constructor')
  })

  it('FINDING: ids are matched exactly, so a differing case is an unknown provider', () => {
    const registry = new Providers([signIn('password')])
    expect(registry.has('Password')).toBe(false)
    expect(() => registry.get('PASSWORD')).toThrow()
  })

  it('FINDING: an unknown id is echoed back inside the error it raises', () => {
    // The id comes from the request. It lands in `meta.providerId` and survives
    // the wire-safe envelope, so whatever a client sends is reflected in the
    // error body.
    const registry = new Providers()
    const err = (() => {
      try {
        registry.get('<script>alert(1)</script>')
      } catch (e) {
        return e as { toJSON(): { error: Record<string, unknown> } }
      }
    })()
    expect(err?.toJSON().error).toMatchObject({ providerId: '<script>alert(1)</script>' })
  })

  it('FINDING: a constructor that throws mid-list leaves a half-built registry', () => {
    // The constructor registers in order, so the duplicate that raises is the
    // fourth call and the first three are already in the map. Nothing unwinds
    // them, and the exception is what a caller sees rather than the state.
    const registry = new Providers()
    expect(() => {
      for (const c of [signIn('a'), signIn('b'), signIn('a')]) registry.register(c)
    }).toThrow()
    expect(registry.list().map((p) => p.id)).toEqual(['a', 'b'])
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
    const registry = new Providers([cap('mfa'), signIn('password')])
    expect(registry.list().map((p) => p.id)).toEqual(['password'])
  })

  it('FINDING: a capability with complete but no begin is advertised and then refused', async () => {
    // `list()` filters on `complete` alone while dispatch requires both. The
    // sign-in grid a client renders therefore offers a provider whose first call
    // fails, and the failure reads as AUTH_PROVIDER_FAILED, which is the same
    // code an unknown id produces.
    const registry = new Providers([cap('half', { complete: async () => [] } as never)])
    expect(registry.list()).toEqual([{ id: 'half', kind: 'test' }])
    await expect(registry.begin('half', ctx, {})).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('a capability with begin but no complete is hidden and also undispatchable', async () => {
    const registry = new Providers([cap('other-half', { begin: async () => [] } as never)])
    expect(registry.list()).toEqual([])
    await expect(registry.begin('other-half', ctx, {})).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
  })

  it('FINDING: an unknown provider and a non-sign-in provider raise the same code', async () => {
    // A caller cannot tell "there is no such provider" from "that provider cannot
    // sign anyone in", so an id-probing client learns the same thing either way.
    // The distinguishing text is in `detail`, which is not a stable contract.
    const registry = new Providers([cap('attach-only')])
    const codeOf = async (id: string): Promise<string | undefined> =>
      registry
        .begin(id, ctx, {})
        .then(() => undefined)
        .catch((e: { code: string }) => e.code)

    expect(await codeOf('attach-only')).toBe(await codeOf('nonexistent'))
  })

  it('dispatches begin and complete to the registered instance with this still bound', async () => {
    class Facet {
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
    const registry = new Providers([new Facet() as never])
    expect(await registry.begin('stateful', ctx, {})).toEqual([{ body: { marker: 'kept' }, status: 200, type: 'json' }])
  })

  it('FINDING: the input is handed to the provider unexamined', async () => {
    // Deliberate, since only the provider knows its own shape, but it means the
    // registry is not a validation boundary: whatever the request body deserialised
    // to arrives as-is.
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

  it('FINDING: a subclass answers a resolve for its base, so registration order decides the winner', () => {
    // `resolve` returns the first instanceof match in insertion order. A plugin
    // that subclasses a shipped facet and registers before it becomes what
    // `auth.passwords`, `auth.mfa` and `auth.apiKeys` return, without ever
    // colliding on an id. Nothing warns that two capabilities answered.
    const shipped = new Base()
    const impostor = new Subclass()

    expect(new Providers([impostor as never, shipped as never]).resolve(Base)).toBe(impostor)
    expect(new Providers([shipped as never, impostor as never]).resolve(Base)).toBe(shipped)
  })

  it('FINDING: resolve reports the first match rather than refusing an ambiguous one', () => {
    // Two independent instances of the same facet class is a configuration error
    // that resolves silently to whichever came first.
    const first = new Base()
    const second = new Base()
    const registry = new Providers([first as never])
    registry.register({ ...second, id: 'base-2' } as never)
    expect(registry.resolve(Base)).toBe(first)
  })

  it('a base instance does not answer a resolve for the subclass', () => {
    expect(new Providers([new Base() as never]).resolve(Subclass)).toBeNull()
  })

  it('FINDING: an object spread from a facet loses its prototype and stops resolving', () => {
    // Spreading a capability to override one field is an ordinary thing to do,
    // and it produces a plain object. The id map still holds it and dispatch
    // still works, so it looks registered, but `auth.passwords` and its siblings
    // return null because the instanceof scan no longer matches.
    const registry = new Providers([{ ...new Base(), id: 'copy' } as never])
    expect(registry.has('copy')).toBe(true)
    expect(registry.resolve(Base)).toBeNull()
  })
})
