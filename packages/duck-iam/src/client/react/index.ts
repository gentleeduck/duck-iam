/**
 * React integration for duck-iam; the provider, hooks, and components come from `createIamAccessControl(React)`.
 * Server-driven (recommended) passes `engine.permissions()` output down; client-evaluated runs an Engine in the browser.
 *
 * Usage (server-driven):
 *
 *   export const { AccessProvider, useAccess, Can } = createIamAccessControl(React)
 *
 *   // Server:
 *   const perms = await engine.permissions(userId, [{ action: "delete", resource: "post" }]);
 *
 *   // Client:
 *   <AccessProvider permissions={perms}><App /></AccessProvider>
 *   const { can } = useAccess();
 *   if (can("manage", "user", undefined, "admin")) { ... }
 *   <Can action="manage" resource="team"><AdminPanel /></Can>
 */

import type { ReactNode } from 'react'
import type { IamClient } from '../../core/types'
import { iamBuildPermissionKey } from '../../shared/keys'
import { iamAllowedActions, iamHasAnyOn, iamPermissionGranted } from '../../shared/permission-map'

/** Re-exported so consumers get key escaping and introspection instead of splitting keys on `':'`. */
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

/** React client types (type-only). Named `IamReactClient` to avoid clashing with the `React` namespace. */
export namespace IamReactClient {
  /** Core types surfaced here so a React-only app need not import `@gentleduck/iam/core`. */
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

/** Message shared by the context default and its tests. */
const MISSING_PROVIDER =
  '[@gentleduck/iam:react] useAccess() called outside <AccessProvider>. ' +
  'Wrap the tree in <AccessProvider permissions={...}> or use createIamPermissionChecker().'

/**
 * Whether a missing provider throws (as Vue does) instead of denying.
 * NOTE: opposite polarity to the devtools guard: only an explicit `'development'` throws, so a bundle
 * with no `process` shim never throws out of a render.
 */
function isDevelopment(): boolean {
  // `process` may be a Node global, a bundler shim, or lack `env`, so each step is checked.
  if (typeof process === 'undefined' || process === null) return false
  const env: unknown = Reflect.get(process, 'env')
  if (env === null || typeof env !== 'object') return false
  return Reflect.get(env, 'NODE_ENV') === 'development'
}

/**
 * Builds the React access control surface (Provider, hooks, components).
 * Call once at app init and export the result so the whole app shares one context.
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

  // SECURITY: outside a provider every member fails closed, and throws in development so the wiring bug shows.
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
      // NOTE: copied in and frozen out, so neither mutating the caller's map nor writing to the exposed
      // `permissions` changes `can()`. Frozen, not copied per read, because consumers use it as a hook dependency.
      const snapshot: IamClient.PartialPermissionMap<TAction, TResource, TScope> = Object.freeze({ ...permissions })
      const can = (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
        const key = iamBuildPermissionKey(action, resource, resourceId, scope)
        return iamPermissionGranted(snapshot, key)
      }

      return {
        permissions: snapshot,
        can,
        cannot: (a: TAction, r: TResource, id?: string, s?: TScope) => !can(a, r, id, s),
        allowedActions: (resource: TResource) => iamAllowedActions(snapshot, resource),
        hasAnyOn: (resource: TResource) => iamHasAnyOn(snapshot, resource),
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

  /**
   * Loading placeholder with a stable identity, so state is not re-set every render.
   * NOTE: frozen because every hook from this factory holds it; a write would grant that key in all of them.
   */
  const EMPTY_PERMISSIONS: IamClient.PartialPermissionMap<TAction, TResource, TScope> = Object.freeze({})

  /**
   * Fetches a permission map and exposes it as React state.
   *
   * @param fetchFn - Loads the permission map (typically one `fetch` call).
   * @param deps - Reload triggers (default `[]`); list the subject id `fetchFn` closes over, or call `refetch`.
   * @returns `{ permissions, can, cannot, allowedActions, hasAnyOn, loading, error, refetch }`.
   */
  function usePermissions(
    fetchFn: () => Promise<IamClient.PartialPermissionMap<TAction, TResource, TScope>>,
    deps: readonly unknown[] = [],
  ) {
    const [permissions, setPermissions] = React.useState(EMPTY_PERMISSIONS)
    const [loading, setLoading] = React.useState(true)
    const [error, setError] = React.useState<Error | null>(null)

    // Run bookkeeping in a `useState` box, since adding `useRef` to `ReactLike` would break hand-built shims.
    // NOTE: `latest` is a run id so a slow earlier load cannot overwrite a newer one; `unmounted` covers teardown.
    const [run] = React.useState(() => ({ fn: fetchFn, latest: 0, unmounted: false }))
    // NOTE: `load` is memoised on `deps`, which exclude `fetchFn`, so it reads `fetchFn` from the box.
    // A captured one would make `refetch()` reload the first render's subject.
    run.fn = fetchFn

    const load = useCallback((): Promise<void> => {
      const id = ++run.latest
      // NOTE: clear the map and error first, so `can()` never serves the previous subject's grants while
      // a refetch is in flight or after it fails. Gate the old UI on `loading` instead.
      setPermissions(EMPTY_PERMISSIONS)
      setError(null)
      setLoading(true)
      const stale = (): boolean => run.unmounted || id !== run.latest
      return run.fn().then(
        (perms: IamClient.PartialPermissionMap<TAction, TResource, TScope>) => {
          if (stale()) return
          setPermissions(perms)
          setLoading(false)
        },
        (err: unknown) => {
          if (stale()) return
          // A rejection can carry a string or a `Response`; normalise it to match `Error | null`.
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
      // Manual reload, matching Vue; needed when a sign-out or account switch does not change `deps`.
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
 * Builds a standalone permission checker for one-off, outside-provider, or non-React checks.
 * Reads and returns the caller's own map, without the copy `AccessProvider` makes.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TScope - Constrains valid scope strings.
 * @param permissions - Provides the permission map (typically from `engine.permissions(...)`).
 * @returns `{ can, cannot, allowedActions, hasAnyOn, permissions }`.
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
