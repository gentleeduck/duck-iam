/**
 * React integration for duck-iam.
 *
 * Two patterns:
 *   1. Server-driven (recommended): generate IamClient.PermissionMap on server, pass to client.
 *   2. IamClient-evaluated: load Engine on client with HttpAdapter or MemoryAdapter.
 *
 * Usage (server-driven):
 *
 *   // Server (Next.js layout, RSC, or API):
 *   const perms = await engine.permissions(userId, [
 *     { action: "create", resource: "post" },
 *     { action: "delete", resource: "post" },
 *     { action: "manage", resource: "team" },
 *   ]);
 *
 *   // IamClient:
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

/** Re-exported: a consumer building a key by hand must use the same escaping. */
export { iamBuildPermissionKey }

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
  // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type -- matches React's own useCallback<T extends Function>
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
  }
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
 * import { createIamAccessControl } from 'duck-iam/client/react'
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

  const AccessContext = createContext<IamReactClient.IContextValue<TAction, TResource, TScope>>({
    permissions: {} as IamClient.PartialPermissionMap<TAction, TResource, TScope>,
    can: () => false,
    cannot: () => true,
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
        return (permissions as Record<string, boolean>)[key] ?? false
      }

      return {
        permissions,
        can,
        cannot: (a: TAction, r: TResource, id?: string, s?: TScope) => !can(a, r, id, s),
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

  /** Hook to asynchronously fetch permissions from a server endpoint. */
  function usePermissions(
    fetchFn: () => Promise<IamClient.PartialPermissionMap<TAction, TResource, TScope>>,
    deps: readonly unknown[] = [],
  ) {
    const [permissions, setPermissions] = React.useState(
      {} as IamClient.PartialPermissionMap<TAction, TResource, TScope>,
    )
    const [loading, setLoading] = React.useState(true)
    const [error, setError] = React.useState<Error | null>(null)

    React.useEffect(() => {
      let cancelled = false
      setLoading(true)
      fetchFn()
        .then((perms: IamClient.PartialPermissionMap<TAction, TResource, TScope>) => {
          if (!cancelled) {
            setPermissions(perms)
            setLoading(false)
          }
        })
        .catch((err: Error) => {
          if (!cancelled) {
            setError(err)
            setLoading(false)
          }
        })
      return () => {
        cancelled = true
      }
    }, deps)

    const can = useCallback(
      (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) => {
        const key = iamBuildPermissionKey(action, resource, resourceId, scope)
        return (permissions as Record<string, boolean>)[key] ?? false
      },
      [permissions],
    )

    return { permissions, can, loading, error }
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
    return (permissions as Record<string, boolean>)[key] ?? false
  }

  return {
    can,
    cannot: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
      return !can(action, resource, resourceId, scope)
    },
    permissions,
  }
}
