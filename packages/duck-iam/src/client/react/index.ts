/**
 * React integration for duck-iam.
 *
 * Two patterns:
 *   1. Server-driven (recommended): generate the permission map on the server, pass it to the client.
 *   2. Client-evaluated: load Engine on the client with HttpAdapter or MemoryAdapter.
 *
 * Every binding below comes from `createIamAccessControl(React)` - nothing in
 * this module is importable directly except that factory and
 * `createIamPermissionChecker`.
 *
 * Usage (server-driven):
 *
 *   import React from 'react'
 *   import { createIamAccessControl } from '@gentleduck/iam/client/react'
 *
 *   export const { AccessProvider, useAccess, Can } = createIamAccessControl(React)
 *
 *   // Server (Next.js layout, RSC, or API):
 *   const perms = await engine.permissions(userId, [
 *     { action: "create", resource: "post" },
 *     { action: "delete", resource: "post" },
 *     { action: "manage", resource: "team" },
 *   ]);
 *
 *   // Client:
 *   <AccessProvider permissions={perms}>
 *     <App />
 *   </AccessProvider>
 *
 *   // In any component:
 *   const { can } = useAccess();
 *   if (can("delete", "post")) { ... }
 *   if (can("manage", "user", undefined, "admin")) { ... }
 *
 *   // Or declaratively:
 *   <Can action="manage" resource="team">
 *     <AdminPanel />
 *   </Can>
 */

import type { ReactNode } from 'react'
import type { IamClient } from '../../core/types'
import { iamBuildPermissionKey } from '../../shared/keys'
import { iamAllowedActions, iamHasAnyOn, iamPermissionGranted } from '../../shared/permission-map'

/** Re-exported: a consumer building a key by hand must use the same escaping. */
/**
 * Re-exported: map introspection used to live only on the vanilla class, so a
 * React consumer who needed "what can this user do here" hand-rolled
 * `key.split(':')` - wrong on every key carrying a scope or an id.
 */
export { iamAllowedActions, iamBuildPermissionKey, iamHasAnyOn }

// React is a peer dep; consumers inject their own React via createIamAccessControl(React).

/** Minimal React context type. */
interface ReactContext<_T> {
  Provider: unknown
}

/** Minimal React API surface for dependency injection. */
interface ReactLike {
  createContext<T>(defaultValue: T): ReactContext<T>
  useContext<T>(context: ReactContext<T>): T
  useMemo<T>(factory: () => T, deps: readonly unknown[]): T
  // `Function` mirrors React's own useCallback<T extends Function> signature.
  useCallback<T extends Function>(callback: T, deps: readonly unknown[]): T
  createElement(type: unknown, props: Record<string, unknown> | null, ...children: ReactNode[]): ReactNode
  useState<T>(initialState: T | (() => T)): [T, (value: T | ((prev: T) => T)) => void]
  useEffect(effect: () => undefined | (() => void), deps?: readonly unknown[]): void
}

/**
 * React client integration types. Type-only namespace - zero bundle cost.
 *
 * Named `IamReactClient` (rather than `React`) to avoid clashing with the React
 * package namespace when consumers import this module alongside React.
 */
export namespace IamReactClient {
  /**
   * The core types a React consumer actually needs, surfaced here.
   *
   * Without these an app using only the React entry still has to import from
   * `@gentleduck/iam/core` to name the map it just received, which puts the core
   * in its dependency list for a type alias.
   */
  export type PermissionMap<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > = IamClient.PartialPermissionMap<TAction, TResource, TScope>

  export type PermissionKey<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > = IamClient.PermissionKey<TAction, TResource, TScope>

  /** One entry of the batch handed to `engine.permissions()`. */
  export type PermissionCheck<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > = IamClient.IPermissionCheck<TAction, TResource, TScope>

  /** What `createIamPermissionChecker` returns, for a consumer holding one. */
  export interface IChecker<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    can: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) => boolean
    cannot: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) => boolean
    allowedActions: (resource: TResource) => string[]
    hasAnyOn: (resource: TResource) => boolean
    permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>
  }

  /**
   * Describes the value exposed by the {@link createIamAccessControl} React context.
   *
   * @template TAction - Constrains valid action strings.
   * @template TResource - Constrains valid resource strings.
   * @template TScope - Constrains valid scope strings.
   */
  export interface IContextValue<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    /** The resolved permission map. */
    permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>
    /** Returns `true` if the action/resource combination is allowed. */
    can: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) => boolean
    /** Returns `true` if the action/resource combination is denied. */
    cannot: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) => boolean
    /** Lists every action granted on `resource` by the current map. */
    allowedActions: (resource: TResource) => string[]
    /** Returns `true` when the current map grants any action on `resource`. */
    hasAnyOn: (resource: TResource) => boolean
  }
}

/**
 * Message shared by the context default and its tests.
 */
const MISSING_PROVIDER =
  '[@gentleduck/iam:react] useAccess() called outside <AccessProvider>. ' +
  'Wrap the tree in <AccessProvider permissions={...}> or use createIamPermissionChecker().'

/**
 * Whether to make a missing provider a hard error.
 *
 * Vue throws for the same wiring bug and React denied silently, so the identical
 * mistake was loud in one framework and invisible in the other - and the silent
 * half looks exactly like a correctly-configured user with no permissions.
 *
 * The polarity is deliberately the opposite of the devtools guard: only an
 * explicit `development` signal throws. No signal denies, because a raw-browser
 * bundle that never shimmed `process` must not start throwing out of a render.
 */
function isDevelopment(): boolean {
  // Read rather than asserted. `process` here is whatever the host bundle put
  // in scope - a Node global, a bundler's shim, an object with no `env` at all -
  // and `as { env?: { NODE_ENV?: string } }` claimed a shape none of those is
  // obliged to have. Every step below is checked, so the answer is `false` for
  // anything that is not literally the string `'development'`, which is the
  // direction this gate must fail in.
  if (typeof process === 'undefined' || process === null) return false
  const env: unknown = Reflect.get(process, 'env')
  if (env === null || typeof env !== 'object') return false
  return Reflect.get(env, 'NODE_ENV') === 'development'
}

/**
 * Builds the React access control surface (Provider, hook, components).
 *
 * Call once at app init and export the result so the entire app shares a
 * single context.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TScope - Constrains valid scope strings.
 * @param React - Provides the host React module so we never bundle our own copy.
 * @returns `{ AccessContext, AccessProvider, useAccess, usePermissions, Can, Cannot }`.
 * @example
 * ```ts
 * import React from 'react'
 * import { createIamAccessControl } from '@gentleduck/iam/client/react'
 *
 * export const { AccessProvider, useAccess, Can, Cannot } = createIamAccessControl(React)
 * ```
 */
export function createIamAccessControl<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(React: ReactLike) {
  const { createContext, useContext, useMemo, useCallback } = React

  // Fail closed in production, loud in development. Every member reports the
  // same wiring bug, so `<Can>` and `allowedActions()` cannot quietly render an
  // empty UI while `useAccess()` would have thrown.
  const outsideProvider = (): never => {
    throw new Error(MISSING_PROVIDER)
  }
  const AccessContext = createContext<IamReactClient.IContextValue<TAction, TResource, TScope>>({
    permissions: {},
    can: () => (isDevelopment() ? outsideProvider() : false),
    cannot: () => (isDevelopment() ? outsideProvider() : true),
    allowedActions: () => (isDevelopment() ? outsideProvider() : []),
    hasAnyOn: () => (isDevelopment() ? outsideProvider() : false),
  })

  /** Context provider component that supplies permission data to the tree. */
  function AccessProvider({
    permissions,
    children,
  }: {
    permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>
    children: ReactNode
  }): ReactNode {
    const value = useMemo(() => {
      const can = (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
        const key = iamBuildPermissionKey(action, resource, resourceId, scope)
        return iamPermissionGranted(permissions, key)
      }

      return {
        permissions,
        can,
        cannot: (a: TAction, r: TResource, id?: string, s?: TScope) => !can(a, r, id, s),
        allowedActions: (resource: TResource) => iamAllowedActions(permissions, resource),
        hasAnyOn: (resource: TResource) => iamHasAnyOn(permissions, resource),
      }
    }, [permissions])

    return React.createElement(AccessContext.Provider, { value }, children)
  }

  /** Hook to access the permission context. */
  function useAccess(): IamReactClient.IContextValue<TAction, TResource, TScope> {
    return useContext(AccessContext)
  }

  /** Declarative component that renders children only when the permission is granted. */
  function Can({
    action,
    resource,
    resourceId,
    scope,
    children,
    fallback = null,
  }: {
    action: TAction
    resource: TResource
    resourceId?: string
    scope?: TScope
    children: ReactNode
    fallback?: ReactNode
  }): ReactNode {
    const { can } = useAccess()
    return can(action, resource, resourceId, scope) ? children : fallback
  }

  /** Declarative component that renders children only when the permission is denied. */
  function Cannot({
    action,
    resource,
    resourceId,
    scope,
    children,
  }: {
    action: TAction
    resource: TResource
    resourceId?: string
    scope?: TScope
    children: ReactNode
  }): ReactNode {
    const { cannot } = useAccess()
    return cannot(action, resource, resourceId, scope) ? children : null
  }

  /** Stable identity: a fresh `{}` per render would re-set state on every run. */
  const EMPTY_PERMISSIONS: IamClient.PartialPermissionMap<TAction, TResource, TScope> = {}

  /**
   * Fetches a permission map and exposes it as React state.
   *
   * @param fetchFn - Loads the permission map (typically one `fetch` call).
   * @param deps - Re-runs the load when these change, like any effect dependency
   *   list. Defaults to `[]`, so a `fetchFn` that closes over a subject id must
   *   list that id here or call `refetch` - otherwise the first subject's grants
   *   are the only ones this hook will ever hold.
   * @returns `{ permissions, can, cannot, allowedActions, hasAnyOn, loading, error, refetch }`.
   */
  function usePermissions(
    fetchFn: () => Promise<IamClient.PartialPermissionMap<TAction, TResource, TScope>>,
    deps: readonly unknown[] = [],
  ) {
    const [permissions, setPermissions] = React.useState(EMPTY_PERMISSIONS)
    const [loading, setLoading] = React.useState(true)
    const [error, setError] = React.useState<Error | null>(null)

    /**
     * Run bookkeeping that survives re-renders without widening `ReactLike`.
     *
     * A `useState` box rather than `useRef` deliberately: `ReactLike` is the
     * shim a consumer injects, and adding a member to it breaks every
     * hand-built one. Lazy initialiser, so the object is created once.
     *
     * `latest` is a monotonic run id, not a boolean. Two loads can be in flight
     * at once - `refetch` called twice, or a deps change racing a manual call -
     * and a slow *earlier* one must not overwrite a fast later one with the
     * previous subject's grants. `unmounted` covers teardown, which a run id
     * cannot see.
     */
    const [run] = React.useState(() => ({ latest: 0, unmounted: false }))

    const load = useCallback((): Promise<void> => {
      const id = ++run.latest
      // A refetch is a different subject until proven otherwise. Holding the
      // previous map made `can()` answer with the last subject's grants for the
      // whole in-flight window, and keep answering with them indefinitely if the
      // refetch failed - the sign-out and account-switch cases. Consumers that
      // want the old UI during a refetch should gate on `loading`, not on stale
      // permissions. `error` is cleared for the same reason: a stale error
      // outlived the failure that caused it.
      setPermissions(EMPTY_PERMISSIONS)
      setError(null)
      setLoading(true)
      const stale = (): boolean => run.unmounted || id !== run.latest
      return fetchFn().then(
        (perms: IamClient.PartialPermissionMap<TAction, TResource, TScope>) => {
          if (stale()) return
          setPermissions(perms)
          setLoading(false)
        },
        (err: unknown) => {
          if (stale()) return
          // `err` is whatever was rejected with, not an `Error` - a rejected
          // `fetch` chain can carry a string or a `Response`. The state is
          // typed `Error | null`, so normalise here rather than let the type
          // describe something the value is not.
          setError(err instanceof Error ? err : new Error(String(err)))
          setLoading(false)
        },
      )
    }, deps)

    React.useEffect(() => {
      run.unmounted = false
      void load()
      return () => {
        run.unmounted = true
      }
    }, deps)

    const can = useCallback(
      (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) => {
        const key = iamBuildPermissionKey(action, resource, resourceId, scope)
        return iamPermissionGranted(permissions, key)
      },
      [permissions],
    )

    return {
      permissions,
      can,
      cannot: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) =>
        !can(action, resource, resourceId, scope),
      allowedActions: (resource: TResource) => iamAllowedActions(permissions, resource),
      hasAnyOn: (resource: TResource) => iamHasAnyOn(permissions, resource),
      loading,
      error,
      // Vue's `usePermissions` has had this since it was written, and its
      // docblock claims the two are the same shape. They were not: without it,
      // the only way to reload was to change `deps`, so a sign-out or an
      // account switch that did not happen to move a dependency left the
      // previous subject's grants in place - the exact case the reset above
      // exists for, unreachable.
      refetch: load,
    }
  }

  return {
    AccessContext,
    AccessProvider,
    useAccess,
    usePermissions,
    Can,
    Cannot,
  }
}

/**
 * Builds a standalone permission checker that does not require React.
 *
 * Useful for one-off checks, hooks outside the provider, or non-React paths.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TScope - Constrains valid scope strings.
 * @param permissions - Provides the permission map (typically from `engine.permissions(...)`).
 * @returns `{ can, cannot, permissions }`.
 */
export function createIamPermissionChecker<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>) {
  const can = (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
    const key = iamBuildPermissionKey(action, resource, resourceId, scope)
    return iamPermissionGranted(permissions, key)
  }

  return {
    can,
    cannot: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
      return !can(action, resource, resourceId, scope)
    },
    allowedActions: (resource: TResource) => iamAllowedActions(permissions, resource),
    hasAnyOn: (resource: TResource) => iamHasAnyOn(permissions, resource),
    permissions,
  }
}
