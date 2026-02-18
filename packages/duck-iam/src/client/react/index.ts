/**
 * React integration for access-engine.
 *
 * Two patterns:
 *   1. Server-driven (recommended): generate PermissionMap on server, pass to client
 *   2. Client-evaluated: load Engine on client with HttpAdapter or MemoryAdapter
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
 *   // Client:
 *   <AccessProvider permissions={perms}>
 *     <App />
 *   </AccessProvider>
 *
 *   // In any component:
 *   const { can } = useAccess();
 *   if (can("delete", "post")) { ... }
 *
 *   // Or declaratively:
 *   <Can action="manage" resource="team">
 *     <AdminPanel />
 *   </Can>
 */

import type { PermissionKey, PermissionMap } from '../../core/types'

// We export factory functions so React is a peer dependency, not a hard one.
// The consuming app calls these with their React import.

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Context + Provider
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export interface AccessContextValue {
  permissions: PermissionMap
  can: (action: string, resource: string, resourceId?: string) => boolean
  cannot: (action: string, resource: string, resourceId?: string) => boolean
}

/**
 * Create the full React access control system.
 * Call once at app init, export the results.
 *
 *   // lib/access.tsx
 *   import React from "react";
 *   import { createAccessControl } from "access-engine/client/react";
 *
 *   export const { AccessProvider, useAccess, Can, Cannot } = createAccessControl(React);
 */
export function createAccessControl(React: any) {
  const { createContext, useContext, useMemo, useCallback } = React

  const AccessContext = createContext<AccessContextValue>({
    permissions: {},
    can: () => false,
    cannot: () => true,
  })

  // ── Provider ──

  function AccessProvider({ permissions, children }: { permissions: PermissionMap; children: any }) {
    const value = useMemo<AccessContextValue>(() => {
      const can = (action: string, resource: string, resourceId?: string): boolean => {
        const key = resourceId ? `${action}:${resource}:${resourceId}` : `${action}:${resource}`
        return permissions[key] ?? false
      }

      return {
        permissions,
        can,
        cannot: (a: string, r: string, id?: string) => !can(a, r, id),
      }
    }, [permissions])

    return React.createElement(AccessContext.Provider, { value }, children)
  }

  // ── Hook ──

  function useAccess(): AccessContextValue {
    return useContext(AccessContext)
  }

  // ── Declarative components ──

  function Can({
    action,
    resource,
    resourceId,
    children,
    fallback = null,
  }: {
    action: string
    resource: string
    resourceId?: string
    children: any
    fallback?: any
  }) {
    const { can } = useAccess()
    return can(action, resource, resourceId) ? children : fallback
  }

  function Cannot({
    action,
    resource,
    resourceId,
    children,
  }: {
    action: string
    resource: string
    resourceId?: string
    children: any
  }) {
    const { cannot } = useAccess()
    return cannot(action, resource, resourceId) ? children : null
  }

  // ── Utility hook: fetch permissions from server ──

  function usePermissions(fetchFn: () => Promise<PermissionMap>, deps: any[] = []) {
    const [permissions, setPermissions] = React.useState<PermissionMap>({})
    const [loading, setLoading] = React.useState(true)
    const [error, setError] = React.useState<Error | null>(null)

    React.useEffect(() => {
      let cancelled = false
      setLoading(true)
      fetchFn()
        .then((perms) => {
          if (!cancelled) {
            setPermissions(perms)
            setLoading(false)
          }
        })
        .catch((err) => {
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
      (action: string, resource: string, resourceId?: string) => {
        const key = resourceId ? `${action}:${resource}:${resourceId}` : `${action}:${resource}`
        return permissions[key] ?? false
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
 * Standalone permission checker (no React context needed).
 * Useful for one-off checks or non-React code.
 */
export function createPermissionChecker(permissions: PermissionMap) {
  return {
    can: (action: string, resource: string, resourceId?: string): boolean => {
      const key = resourceId ? `${action}:${resource}:${resourceId}` : `${action}:${resource}`
      return permissions[key] ?? false
    },
    cannot: (action: string, resource: string, resourceId?: string): boolean => {
      const key = resourceId ? `${action}:${resource}:${resourceId}` : `${action}:${resource}`
      return !(permissions[key] ?? false)
    },
    permissions,
  }
}
