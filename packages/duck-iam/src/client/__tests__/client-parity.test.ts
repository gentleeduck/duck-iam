import { afterEach, describe, expect, it } from 'vitest'
import type { IamClient } from '../../core/types'
import { iamBuildPermissionKey } from '../../shared/keys'
import { createIamAccessControl, createIamPermissionChecker, type IamReactClient } from '../react'
import { IamAccessClient } from '../vanilla'
import { createIamVueAccess } from '../vue'

// Drives one map through the React, Vue, and vanilla clients and compares the answers,
// since `SECURITY.md` treats the three as one supported surface.

/** Default `string` params: this is unvalidated server JSON, and the escaped key has no narrowed type. */
const MAP: IamClient.PartialPermissionMap = {
  '@org-1:read:post': true,
  'delete:post': true,
  // A resource whose own name contains the separator, escaped by the builder.
  [iamBuildPermissionKey('read', 'a:b')]: true,
  'read:comment': true,
  'read:post': true,
  'read:post:42': true,
  // Present but not granted: `=== true`, never truthiness.
  'write:post': false,
}

/** Narrows what the fake React captured, checking every member so a partial context cannot pass. */
function isContextValue(value: unknown): value is IamReactClient.IContextValue {
  if (typeof value !== 'object' || value === null) return false
  for (const member of ['can', 'cannot', 'allowedActions', 'hasAnyOn']) {
    if (typeof Reflect.get(value, member) !== 'function') return false
  }
  return typeof Reflect.get(value, 'permissions') === 'object'
}

/** Enough of React for the bindings under test; no `as never` at the call site. */
function makeReact() {
  const contextDefaults: unknown[] = []
  const rendered: unknown[] = []

  const React = {
    // biome-ignore lint/complexity/noBannedTypes: matches React's own useCallback signature
    useCallback: <T extends Function>(cb: T): T => cb,
    createContext: <T>(value: T) => {
      contextDefaults.push(value)
      return { Provider: null }
    },
    createElement: (_type: unknown, props: Record<string, unknown> | null) => {
      rendered.push(props?.value)
      return null
    },
    useContext: <T>(_context: { Provider: unknown }): T => {
      // Tests read captured values instead; a silent `undefined` here would pass assertions for the wrong reason.
      throw new Error('fake React: read contextDefault()/providedValue() instead of useContext()')
    },
    useEffect: () => undefined,
    useMemo: <T>(factory: () => T): T => factory(),
    // Only `usePermissions` uses state and nothing here drives it; throw rather than freeze state.
    useState: <T>(_initialState: T | (() => T)): [T, (value: T | ((prev: T) => T)) => void] => {
      throw new Error('fake React: usePermissions is not exercised here')
    },
  }

  /** The value `createContext` was given: the outside-a-provider behaviour. */
  const contextDefault = (): IamReactClient.IContextValue => {
    const value = contextDefaults[0]
    if (!isContextValue(value)) throw new Error('fake React captured no context value')
    return value
  }

  /** The value the provider passed down. */
  const providedValue = (): IamReactClient.IContextValue => {
    const value = rendered[rendered.length - 1]
    if (!isContextValue(value)) throw new Error('fake React captured no provider value')
    return value
  }

  return { React, contextDefault, providedValue }
}

/** Enough of Vue for `createAccessState`; `inject` is never provided here. */
function makeVue() {
  return {
    computed: <T>(getter: () => T) => ({
      get value() {
        return getter()
      },
    }),
    defineComponent: (options: Record<string, unknown>) => options,
    h: (type: unknown, props?: Record<string, unknown> | null, children?: unknown) => ({ children, props, type }),
    inject: () => undefined,
    provide: () => undefined,
    ref: <T>(value: T) => ({ value }),
  }
}

/** The three surfaces, each already holding {@link MAP}. */
function surfaces() {
  const react = createIamPermissionChecker(MAP)
  const vue = createIamVueAccess(makeVue()).createAccessState(MAP)
  const vanilla = new IamAccessClient(MAP)
  return [
    { name: 'react', ...react },
    { name: 'vue', ...vue },
    {
      allowedActions: (r: string) => vanilla.allowedActions(r),
      can: (a: string, r: string, id?: string, s?: string) => vanilla.can(a, r, id, s),
      cannot: (a: string, r: string, id?: string, s?: string) => vanilla.cannot(a, r, id, s),
      hasAnyOn: (r: string) => vanilla.hasAnyOn(r),
      name: 'vanilla',
    },
  ]
}

describe('the three clients answer the same map identically', () => {
  const CHECKS: ReadonlyArray<{ args: [string, string, string?, string?]; expected: boolean }> = [
    { args: ['read', 'post'], expected: true },
    { args: ['delete', 'post'], expected: true },
    // Value is `false`, not absent: a truthiness test would grant it.
    { args: ['write', 'post'], expected: false },
    { args: ['read', 'post', '42'], expected: true },
    { args: ['read', 'post', '43'], expected: false },
    { args: ['read', 'post', undefined, 'org-1'], expected: true },
    { args: ['read', 'post', undefined, 'org-2'], expected: false },
    // The escaped key round-trips through the builder on all three.
    { args: ['read', 'a:b'], expected: true },
    { args: ['manage', 'post'], expected: false },
  ]

  for (const { args, expected } of CHECKS) {
    it(`can(${JSON.stringify(args)}) === ${expected} everywhere`, () => {
      const answers = surfaces().map((s) => s.can(...args))
      expect(answers).toEqual([expected, expected, expected])
      expect(surfaces().map((s) => s.cannot(...args))).toEqual([!expected, !expected, !expected])
    })
  }

  // A naive `key.split(':')` reads `@org-1` as an action and `b` or `42` as resources; no client may.
  const INTROSPECTION: ReadonlyArray<{ actions: string[]; any: boolean; resource: string }> = [
    { actions: ['delete', 'read'], any: true, resource: 'post' },
    { actions: ['read'], any: true, resource: 'comment' },
    { actions: ['read'], any: true, resource: 'a:b' },
    { actions: [], any: false, resource: 'billing' },
    // The naive split's answers, none of which name a real resource.
    { actions: [], any: false, resource: '42' },
    { actions: [], any: false, resource: 'b' },
  ]

  for (const { actions, any, resource } of INTROSPECTION) {
    it(`allowedActions(${JSON.stringify(resource)}) agrees on all three`, () => {
      expect(surfaces().map((s) => s.allowedActions(resource).sort())).toEqual([actions, actions, actions])
      expect(surfaces().map((s) => s.hasAnyOn(resource))).toEqual([any, any, any])
    })
  }
})

/** Parses a map as it arrives (unvalidated JSON), so tests can pass values a `boolean` map type cannot express. */
function fromJson(json: string): IamClient.PartialPermissionMap {
  return JSON.parse(json)
}

describe('a grant is the boolean `true`, never merely truthy', () => {
  // `"false"`, `1`, and `{}` are truthy; reading any of them as a grant fails open in `can()` and `allowedActions()`.
  const HOSTILE = fromJson('{"read:post":"false","write:post":1,"admin:post":{},"delete:post":true}')

  function hostileSurfaces() {
    const react = createIamPermissionChecker(HOSTILE)
    const vue = createIamVueAccess(makeVue()).createAccessState(HOSTILE)
    const vanilla = new IamAccessClient(HOSTILE)
    return [
      { name: 'react', ...react },
      { name: 'vue', ...vue },
      {
        allowedActions: (r: string) => vanilla.allowedActions(r),
        can: (a: string, r: string, id?: string, s?: string) => vanilla.can(a, r, id, s),
        hasAnyOn: (r: string) => vanilla.hasAnyOn(r),
        name: 'vanilla',
      },
    ]
  }

  for (const action of ['read', 'write', 'admin']) {
    it(`can('${action}', 'post') is false on all three`, () => {
      expect(hostileSurfaces().map((s) => s.can(action, 'post'))).toEqual([false, false, false])
    })
  }

  it('allowedActions lists only the genuinely granted action', () => {
    expect(hostileSurfaces().map((s) => s.allowedActions('post'))).toEqual([['delete'], ['delete'], ['delete']])
  })

  it('hasAnyOn is still true, because one real grant remains', () => {
    expect(hostileSurfaces().map((s) => s.hasAnyOn('post'))).toEqual([true, true, true])
  })

  // Control: strip the one real grant and the whole resource goes dark.
  it('reports nothing when every value is merely truthy', () => {
    const onlyTruthy = fromJson('{"read:post":"false","write:post":1}')
    expect(new IamAccessClient(onlyTruthy).allowedActions('post')).toEqual([])
    expect(new IamAccessClient(onlyTruthy).hasAnyOn('post')).toBe(false)
  })
})

describe('react reports a missing provider the way vue does', () => {
  const original = process.env.NODE_ENV

  afterEach(() => {
    process.env.NODE_ENV = original
  })

  it('throws in development, on every member of the context', () => {
    process.env.NODE_ENV = 'development'
    const { React, contextDefault } = makeReact()
    createIamAccessControl(React)
    const ctx = contextDefault()
    expect(() => ctx.can('read', 'post')).toThrow(/outside <AccessProvider>/)
    expect(() => ctx.cannot('read', 'post')).toThrow(/outside <AccessProvider>/)
    expect(() => ctx.allowedActions('post')).toThrow(/outside <AccessProvider>/)
    expect(() => ctx.hasAnyOn('post')).toThrow(/outside <AccessProvider>/)
  })

  it('still fails closed in production rather than throwing out of a render', () => {
    process.env.NODE_ENV = 'production'
    const { React, contextDefault } = makeReact()
    createIamAccessControl(React)
    const ctx = contextDefault()
    expect(ctx.can('read', 'post')).toBe(false)
    expect(ctx.cannot('read', 'post')).toBe(true)
    expect(ctx.allowedActions('post')).toEqual([])
    expect(ctx.hasAnyOn('post')).toBe(false)
    expect(ctx.permissions).toEqual({})
  })

  // Without an explicit development signal, deny rather than throw out of a render.
  it('denies rather than throws when there is no signal', () => {
    process.env.NODE_ENV = 'test'
    const { React, contextDefault } = makeReact()
    createIamAccessControl(React)
    const ctx = contextDefault()
    expect(ctx.can('read', 'post')).toBe(false)
    expect(ctx.hasAnyOn('post')).toBe(false)
  })

  // Control: the throwing default must not leak into a correctly wired tree.
  it('a provider inside the same development build still answers from its map', () => {
    process.env.NODE_ENV = 'development'
    const { React, providedValue } = makeReact()
    const { AccessProvider } = createIamAccessControl(React)
    AccessProvider({ children: null, permissions: MAP })
    const ctx = providedValue()
    expect(ctx.can('read', 'post')).toBe(true)
    expect(ctx.can('write', 'post')).toBe(false)
    expect(ctx.allowedActions('post').sort()).toEqual(['delete', 'read'])
    expect(ctx.hasAnyOn('billing')).toBe(false)
  })
})

describe('vue has an async path with the same shape react has', () => {
  it('starts empty and loading, then serves the fetched map', async () => {
    const { usePermissions } = createIamVueAccess(makeVue())
    const state = usePermissions(async () => MAP)

    expect(state.loading.value).toBe(true)
    expect(state.can('read', 'post')).toBe(false)

    await state.refetch()

    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBeNull()
    expect(state.can('read', 'post')).toBe(true)
    expect(state.allowedActions('post').sort()).toEqual(['delete', 'read'])
    expect(state.hasAnyOn('post')).toBe(true)
  })

  // The previous subject's grants must not survive an in-flight or failed refetch.
  it('drops the previous subject the moment a refetch starts', async () => {
    const { usePermissions } = createIamVueAccess(makeVue())
    let current: IamClient.PartialPermissionMap = { 'delete:post': true }
    const state = usePermissions(async () => current)
    await state.refetch()
    expect(state.can('delete', 'post')).toBe(true)

    current = { 'read:post': true }
    const inFlight = state.refetch()
    expect(state.loading.value).toBe(true)
    expect(state.can('delete', 'post')).toBe(false)
    await inFlight
    expect(state.can('delete', 'post')).toBe(false)
    expect(state.can('read', 'post')).toBe(true)
  })

  it('does not keep the old map when the refetch fails', async () => {
    const { usePermissions } = createIamVueAccess(makeVue())
    let fail = false
    const state = usePermissions(async () => {
      if (fail) throw new Error('session expired')
      return MAP
    })
    await state.refetch()
    expect(state.can('read', 'post')).toBe(true)

    fail = true
    await state.refetch()
    expect(state.can('read', 'post')).toBe(false)
    expect(state.error.value?.message).toBe('session expired')
    expect(state.loading.value).toBe(false)
  })

  // Two loads overlap and the slow earlier one resolves last; it must not win.
  it('a superseded slow fetch never overwrites a newer one', async () => {
    const { usePermissions } = createIamVueAccess(makeVue())
    const gates: Array<(map: IamClient.PartialPermissionMap) => void> = []
    const state = usePermissions(() => new Promise<IamClient.PartialPermissionMap>((resolve) => gates.push(resolve)))

    // The composable loads once on creation, so that call holds gate 0.
    expect(gates).toHaveLength(1)

    const first = state.refetch()
    const second = state.refetch()
    // Later request settles first, earlier one arrives afterwards.
    gates[2]?.({ 'read:post': true })
    await second
    gates[1]?.({ 'delete:post': true })
    await first

    expect(state.can('read', 'post')).toBe(true)
    expect(state.can('delete', 'post')).toBe(false)
  })
})
