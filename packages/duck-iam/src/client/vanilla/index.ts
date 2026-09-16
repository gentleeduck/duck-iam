/**
 * Framework-agnostic client access control, for vanilla JS, Web Components, Svelte, Solid, or Angular.
 *
 * Usage:
 *
 *   const access = new IamAccessClient(permissionsFromServer);
 *   access.can("manage", "user", undefined, "admin"); // scoped check
 *   access.subscribe((perms) => { rerender(); });
 *   access.update(newPermissions);
 *
 *   // Or fetch from server
 *   const access = await IamAccessClient.fromServer("/api/permissions", {
 *     headers: { Authorization: "Bearer ..." },
 *   });
 */

import type { IamClient } from '../../core/types'
import { iamBuildPermissionKey } from '../../shared/keys'
import { iamAllowedActions, iamHasAnyOn, iamPermissionGranted } from '../../shared/permission-map'

/** Re-exported so consumers get map introspection instead of splitting keys on `':'`. */
export { iamAllowedActions, iamHasAnyOn }

/** Listener run on {@link IamAccessClient.update} or {@link IamAccessClient.merge}. */
type Listener<TAction extends string = string, TResource extends string = string, TScope extends string = string> = (
  permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>,
) => void

/**
 * Wraps a {@link IamClient.PartialPermissionMap} with `.can()`/`.cannot()` checks and `.subscribe()` for updates.
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
  private _permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>
  private _listeners = new Set<Listener<TAction, TResource, TScope>>()

  /**
   * Creates a new client over a copy of the given permission map.
   *
   * @param permissions - Optional initial permission map (set later via `update`).
   */
  constructor(permissions?: IamClient.PartialPermissionMap<TAction, TResource, TScope>) {
    // NOTE: copied in here and out in the getter. `Readonly` erases at runtime, so a shared reference would let
    // `map.x = true` grant without `update()`/`merge()` and without notifying subscribers.
    this._permissions = { ...permissions }
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
    // `Headers`, not a spread: spreading a `Headers` instance or a tuple list drops every header in it.
    const headers = new Headers(init?.headers)
    if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const res = await fetch(url, { ...init, headers })
    if (!res.ok) throw new Error(`Failed to fetch permissions: ${res.status}`)
    const perms: IamClient.PartialPermissionMap<TA, TR, TS> = await res.json()
    return new IamAccessClient<TA, TR, TS>(perms)
  }

  /**
   * Returns a copy of the current permission map, so an in-place edit cannot bypass `update()`/`merge()`.
   *
   * @returns Readonly map of action/resource keys to boolean grants.
   */
  get permissions(): Readonly<IamClient.PartialPermissionMap<TAction, TResource, TScope>> {
    return { ...this._permissions }
  }

  /** Returns whether the map grants the action on the resource (optionally one instance, within a scope). */
  can(action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean {
    const key = iamBuildPermissionKey(action, resource, resourceId, scope)
    return iamPermissionGranted(this._permissions, key)
  }

  /** Negation of {@link IamAccessClient.can}. */
  cannot(action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean {
    return !this.can(action, resource, resourceId, scope)
  }

  /** Replaces the permission map and notifies subscribers; a throwing listener does not block the others. */
  update(permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>): void {
    // Copied in, as in the constructor. Listeners get the caller's object, which cannot reach the stored map.
    this._permissions = { ...permissions }
    for (const fn of this._listeners) {
      try {
        fn(permissions)
      } catch (err) {
        // Surface the throw without aborting the remaining listeners.
        console.error('[@gentleduck/iam:client] listener threw - continuing to notify others', err)
      }
    }
  }

  /** Shallow-merges the given map into the current permissions and notifies subscribers. */
  merge(permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>): void {
    this.update({ ...this._permissions, ...permissions })
  }

  /**
   * Registers a listener to run on every permission change.
   * @returns An unsubscribe function.
   */
  subscribe(fn: Listener<TAction, TResource, TScope>): () => void {
    this._listeners.add(fn)
    return () => this._listeners.delete(fn)
  }

  /**
   * Lists the deduplicated actions granted on `resource`, ignoring keys not built by `iamBuildPermissionKey`.
   * Returns `string[]`, not `TAction[]`, because the map is unvalidated JSON; see {@link iamAllowedActions}.
   */
  allowedActions(resource: TResource): string[] {
    return iamAllowedActions(this._permissions, resource)
  }

  /** Returns whether at least one action is granted on the resource. */
  hasAnyOn(resource: TResource): boolean {
    return iamHasAnyOn(this._permissions, resource)
  }
}

/** Factory around {@link IamAccessClient}, for callers who prefer functions to `new`. */
export function iamAccessClient(...args: ConstructorParameters<typeof IamAccessClient>): IamAccessClient {
  return new IamAccessClient(...args)
}
