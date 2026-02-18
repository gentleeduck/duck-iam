/**
 * Framework-agnostic client-side access control.
 *
 * Use when you don't use React/Vue, or for Web Components,
 * Svelte, Solid, Angular, or vanilla JS.
 *
 * Usage:
 *
 *   import { AccessClient } from "access-engine/client/vanilla";
 *
 *   // Initialize from server-provided permissions
 *   const access = new AccessClient(permissionsFromServer);
 *
 *   // Check
 *   access.can("delete", "post");       // boolean
 *   access.cannot("manage", "billing"); // boolean
 *
 *   // With change listener (for reactive frameworks)
 *   access.subscribe((perms) => { rerender(); });
 *   access.update(newPermissions);
 *
 *   // Or fetch from server
 *   const access = await AccessClient.fromServer("/api/permissions", {
 *     headers: { Authorization: "Bearer ..." },
 *   });
 */

import type { PermissionMap } from '../../core/types'

type Listener = (permissions: PermissionMap) => void

export class AccessClient {
  private _permissions: PermissionMap
  private _listeners = new Set<Listener>()

  constructor(permissions: PermissionMap = {}) {
    this._permissions = permissions
  }

  /** Fetch permissions from a server endpoint */
  static async fromServer(url: string, init?: RequestInit): Promise<AccessClient> {
    const res = await fetch(url, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    })
    if (!res.ok) throw new Error(`Failed to fetch permissions: ${res.status}`)
    const perms: PermissionMap = await res.json()
    return new AccessClient(perms)
  }

  get permissions(): Readonly<PermissionMap> {
    return this._permissions
  }

  can(action: string, resource: string, resourceId?: string): boolean {
    const key = resourceId ? `${action}:${resource}:${resourceId}` : `${action}:${resource}`
    return this._permissions[key] ?? false
  }

  cannot(action: string, resource: string, resourceId?: string): boolean {
    return !this.can(action, resource, resourceId)
  }

  /** Update permissions and notify listeners */
  update(permissions: PermissionMap): void {
    this._permissions = permissions
    for (const fn of this._listeners) fn(permissions)
  }

  /** Merge new permissions into existing */
  merge(permissions: PermissionMap): void {
    this.update({ ...this._permissions, ...permissions })
  }

  /** Subscribe to permission changes. Returns unsubscribe function. */
  subscribe(fn: Listener): () => void {
    this._listeners.add(fn)
    return () => this._listeners.delete(fn)
  }

  /** Get all allowed actions for a resource type */
  allowedActions(resource: string): string[] {
    const actions: string[] = []
    for (const [key, allowed] of Object.entries(this._permissions)) {
      if (!allowed) continue
      const parts = key.split(':')
      if (parts[1] === resource) {
        actions.push(parts[0])
      }
    }
    return [...new Set(actions)]
  }

  /** Check if the user has any permission on a resource */
  hasAnyOn(resource: string): boolean {
    return Object.entries(this._permissions).some(([key, allowed]) => allowed && key.split(':')[1] === resource)
  }
}
