/**
 * Framework-agnostic client-side access control.
 *
 * Use when you don't use React/Vue, or for Web Components,
 * Svelte, Solid, Angular, or vanilla JS.
 *
 * Usage:
 *
 *   import { IamAccessClient } from "@gentleduck/iam/client/vanilla";
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
import { iamBuildPermissionKey } from '../../shared/keys'
import { iamAllowedActions, iamHasAnyOn, iamPermissionGranted } from '../../shared/permission-map'

/**
 * Re-exported so a React or Vue app reaches the same map introspection this
 * class has always had, instead of hand-rolling `key.split(':')`.
 */
export { iamAllowedActions, iamHasAnyOn }

/** Callback invoked when permissions are updated via {@link IamAccessClient.update} or {@link IamAccessClient.merge}. */
type Listener<TAction extends string = string, TResource extends string = string, TScope extends string = string> = (
  permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>,
) => void

/**
 * Provides framework-agnostic client-side access control.
 *
 * Wraps a {@link IamClient.PartialPermissionMap} (typically fetched from the server) and
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
  private _permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>
  private _listeners = new Set<Listener<TAction, TResource, TScope>>()

  /**
   * Creates a new client wrapping the given permission map.
   *
   * @param permissions - Optional initial permission map (set later via `update`).
   */
  constructor(permissions?: IamClient.PartialPermissionMap<TAction, TResource, TScope>) {
    // Copied, for the reason the `permissions` getter copies on the way out:
    // the map is a plain object and `Readonly<...>` erases at runtime, so
    // holding the caller's reference let `map.x = true` after construction
    // grant a permission without going through `update()`/`merge()` - and
    // therefore without notifying a single subscriber. The guard was written
    // on the reading side only; the writing side is the same hazard.
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
    const res = await fetch(url, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    })
    if (!res.ok) throw new Error(`Failed to fetch permissions: ${res.status}`)
    const perms: IamClient.PartialPermissionMap<TA, TR, TS> = await res.json()
    return new IamAccessClient<TA, TR, TS>(perms)
  }

  /**
   * Returns a copy of the current permission map.
   *
   * A copy, not the live object: `Readonly<...>` erases at runtime, so handing
   * out the internal map let an in-place edit grant a permission without going
   * through `update()`/`merge()` - and therefore without notifying subscribers.
   *
   * @returns Readonly map of action/resource keys to boolean grants.
   */
  get permissions(): Readonly<IamClient.PartialPermissionMap<TAction, TResource, TScope>> {
    return { ...this._permissions }
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
    return iamPermissionGranted(this._permissions, key)
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
  update(permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>): void {
    // Copied in, for the reason the constructor copies. Listeners still receive
    // the caller's own object: whatever a listener does to it is between the
    // listener and the caller, and it can no longer reach what this client
    // decides from.
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

  /**
   * Shallow-merges the given map into the current permissions and notifies subscribers.
   *
   * @param permissions - Provides the partial permission patch.
   * @returns Nothing.
   */
  merge(permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>): void {
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
   * Keys not produced by `iamBuildPermissionKey` are ignored. Returns `string[]`
   * rather than `TAction[]`: see {@link iamAllowedActions} for why re-asserting
   * the caller's union over unvalidated server JSON is not a claim this class
   * can honestly make.
   *
   * @param resource - Specifies the resource type to filter by.
   * @returns Deduplicated array of actions allowed on `resource`.
   */
  allowedActions(resource: TResource): string[] {
    return iamAllowedActions(this._permissions, resource)
  }

  /**
   * Returns whether at least one action is allowed on the resource.
   *
   * @param resource - Specifies the resource type to probe.
   * @returns `true` when any granted key targets the resource.
   */
  hasAnyOn(resource: TResource): boolean {
    return iamHasAnyOn(this._permissions, resource)
  }
}

/** Factory around {@link IamAccessClient}, for callers who prefer functions to `new`. */
export function iamAccessClient(...args: ConstructorParameters<typeof IamAccessClient>): IamAccessClient {
  return new IamAccessClient(...args)
}
