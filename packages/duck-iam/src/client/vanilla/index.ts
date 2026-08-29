/**
 * Framework-agnostic client-side access control.
 *
 * Use when you don't use React/Vue, or for Web Components,
 * Svelte, Solid, Angular, or vanilla JS.
 *
 * Usage:
 *
 *   import { IamAccessClient } from "duck-iam/client/vanilla";
 *
 *   // Initialize from server-provided permissions
 *   const access = new IamAccessClient(permissionsFromServer);
 *
 *   // Check
 *   access.can("delete", "post");                    // boolean
 *   access.can("manage", "user", undefined, "admin"); // scoped check
 *   access.cannot("manage", "billing");               // boolean
 *
 *   // With change listener (for reactive frameworks)
 *   access.subscribe((perms) => { rerender(); });
 *   access.update(newPermissions);
 *
 *   // Or fetch from server
 *   const access = await IamAccessClient.fromServer("/api/permissions", {
 *     headers: { Authorization: "Bearer ..." },
 *   });
 */

import type { IamClient } from '../../core/types'
import { iamBuildPermissionKey, iamSplitPermissionKey } from '../../shared/keys'

/** Callback invoked when permissions are updated via {@link IamAccessClient.update} or {@link IamAccessClient.merge}. */
type Listener<TAction extends string = string, TResource extends string = string, TScope extends string = string> = (
  permissions: IamClient.PermissionMap<TAction, TResource, TScope>,
) => void

/**
 * Provides framework-agnostic client-side access control.
 *
 * Wraps a {@link IamClient.PermissionMap} (typically fetched from the server) and
 * exposes `.can()` / `.cannot()` checks. Supports reactive updates via
 * `.subscribe()`.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TScope - Constrains valid scope strings.
 * @example
 * ```ts
 * const access = new IamAccessClient(permissionsFromServer)
 * if (access.can('delete', 'post')) deleteIt()
 * const unsub = access.subscribe(() => rerender())
 * ```
 */
export class IamAccessClient<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> {
  private _permissions: IamClient.PermissionMap<TAction, TResource, TScope>
  private _listeners = new Set<Listener<TAction, TResource, TScope>>()

  /**
   * Creates a new client wrapping the given permission map.
   *
   * @param permissions - Optional initial permission map (set later via `update`).
   */
  constructor(permissions?: IamClient.PermissionMap<TAction, TResource, TScope>) {
    this._permissions = permissions ?? ({} as IamClient.PermissionMap<TAction, TResource, TScope>)
  }

  /**
   * Fetches a permission map from `url` and returns a populated client.
   *
   * @template TA - Constrains valid action strings.
   * @template TR - Constrains valid resource strings.
   * @template TS - Constrains valid scope strings.
   * @param url - Specifies the endpoint that returns a JSON permission map.
   * @param init - Optional `fetch` init (auth headers, signal, etc.).
   * @returns A populated {@link IamAccessClient}.
   * @throws Error when the response status is non-2xx.
   */
  static async fromServer<TA extends string = string, TR extends string = string, TS extends string = string>(
    url: string,
    init?: RequestInit,
  ): Promise<IamAccessClient<TA, TR, TS>> {
    const res = await fetch(url, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    })
    if (!res.ok) throw new Error(`Failed to fetch permissions: ${res.status}`)
    const perms: IamClient.PermissionMap<TA, TR, TS> = await res.json()
    return new IamAccessClient<TA, TR, TS>(perms)
  }

  /**
   * Returns a readonly view of the current permission map.
   *
   * @returns Readonly map of action/resource keys to boolean grants.
   */
  get permissions(): Readonly<IamClient.PermissionMap<TAction, TResource, TScope>> {
    return this._permissions
  }

  /**
   * Returns whether the action is granted on the resource.
   *
   * @param action - Specifies the action being checked.
   * @param resource - Specifies the resource type.
   * @param resourceId - Optional resource instance ID.
   * @param scope - Optional scope binding the check.
   * @returns `true` when the permission map grants the combination.
   */
  can(action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean {
    const key = iamBuildPermissionKey(action, resource, resourceId, scope)
    return (this._permissions as Record<string, boolean>)[key] ?? false
  }

  /**
   * Returns whether the action is denied on the resource.
   *
   * @param action - Specifies the action being checked.
   * @param resource - Specifies the resource type.
   * @param resourceId - Optional resource instance ID.
   * @param scope - Optional scope binding the check.
   * @returns `true` when the permission map does not grant the combination.
   */
  cannot(action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean {
    return !this.can(action, resource, resourceId, scope)
  }

  /**
   * Replaces the current permission map and notifies subscribers.
   *
   * Listener errors are caught so one failing handler cannot block others.
   *
   * @param permissions - Provides the new permission map.
   * @returns Nothing.
   */
  update(permissions: IamClient.PermissionMap<TAction, TResource, TScope>): void {
    this._permissions = permissions
    for (const fn of this._listeners) {
      try {
        fn(permissions)
      } catch (err) {
        // Surface the throw without aborting other listeners.
        // eslint-disable-next-line no-console
        console.error('[@gentleduck/iam:client] listener threw - continuing to notify others', err)
      }
    }
  }

  /**
   * Shallow-merges the given map into the current permissions and notifies subscribers.
   *
   * @param permissions - Provides the partial permission patch.
   * @returns Nothing.
   */
  merge(permissions: IamClient.PermissionMap<TAction, TResource, TScope>): void {
    this.update({ ...this._permissions, ...permissions })
  }

  /**
   * Registers a listener to run on every permission change.
   *
   * @param fn - Listener invoked with the new permission map.
   * @returns An unsubscribe function.
   */
  subscribe(fn: Listener<TAction, TResource, TScope>): () => void {
    this._listeners.add(fn)
    return () => this._listeners.delete(fn)
  }

  /**
   * Lists every action allowed against the given resource type.
   *
   * Handles all key formats produced by `iamBuildPermissionKey`:
   * `action:resource`, `action:resource:resourceId`, `scope:action:resource`,
   * and `scope:action:resource:resourceId`.
   *
   * @param resource - Specifies the resource type to filter by.
   * @returns Deduplicated array of actions allowed on `resource`.
   */
  allowedActions(resource: TResource): TAction[] {
    const actions: TAction[] = []
    for (const [key, allowed] of Object.entries(this._permissions)) {
      if (!allowed) continue
      const action = extractAction(key, resource)
      if (action) actions.push(action as TAction)
    }
    return [...new Set(actions)]
  }

  /**
   * Returns whether at least one action is allowed on the resource.
   *
   * @param resource - Specifies the resource type to probe.
   * @returns `true` when any granted key targets the resource.
   */
  hasAnyOn(resource: TResource): boolean {
    return Object.entries(this._permissions).some(([key, allowed]) => {
      if (!allowed) return false
      return extractAction(key, resource) !== null
    })
  }
}

/**
 * Extract the action from a permission key for a given resource.
 *
 * Key formats (from iamBuildPermissionKey):
 *   "action:resource"
 *   "action:resource:resourceId"
 *   "scope:action:resource"
 *   "scope:action:resource:resourceId"
 *
 * Rather than guessing the format from part count (ambiguous for 3 parts),
 * we check if the resource appears at the expected position for each format.
 */
function extractAction(key: string, resource: string): string | null {
  // iamSplitPermissionKey honours `\:` / `\\` escapes; naive split mis-tokenises.
  const parts = iamSplitPermissionKey(key)

  switch (parts.length) {
    case 2:
      // action:resource
      if (parts[1] === resource) return parts[0] as string
      return null
    case 3:
      // Could be action:resource:resourceId OR scope:action:resource.
      // Check both: resource at index 1 (unscoped) or index 2 (scoped).
      if (parts[1] === resource) return parts[0] as string
      if (parts[2] === resource) return parts[1] as string
      return null
    case 4:
      // scope:action:resource:resourceId
      if (parts[2] === resource) return parts[1] as string
      return null
    default:
      return null
  }
}

/** Factory around {@link IamAccessClient}, for callers who prefer functions to `new`. */
export function iamAccessClient(...args: ConstructorParameters<typeof IamAccessClient>): IamAccessClient {
  return new IamAccessClient(...args)
}
