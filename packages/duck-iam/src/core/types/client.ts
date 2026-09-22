import type { IamPrimitives } from './primitives'

/** Types derived from the caller's declared actions, resources and scopes. Type-only. */
export namespace IamClient {
  /**
   * Key of one permission check in a {@link PermissionMap}; formats:
   *  - `action:resource`
   *  - `action:resource:resourceId`
   *  - `@scope:action:resource`
   *  - `@scope:action:resource:resourceId`
   *
   * `@` marks a scope so three segments are never ambiguous; segments are escaped by `iamBuildPermissionKey`.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   */
  export type PermissionKey<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > =
    | `${TAction}:${TResource}`
    | `${TAction}:${TResource}:${string}`
    | `@${TScope}:${TAction}:${TResource}`
    | `@${TScope}:${TAction}:${TResource}:${string}`

  /**
   * Map from {@link PermissionKey} to result, with every combination present. See {@link PartialPermissionMap}.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   */
  export type PermissionMap<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > = Record<PermissionKey<TAction, TResource, TScope>, boolean>

  /**
   * What `engine.permissions()` returns: only the keys that were checked.
   * Lookups default a missing key to `false`, so it behaves like {@link PermissionMap} at runtime.
   */
  export type PartialPermissionMap<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > = Partial<PermissionMap<TAction, TResource, TScope>>

  /**
   * One check for batch evaluation via `engine.permissions()` or `access.checks()`.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   */
  export interface IPermissionCheck<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    /** The action to check. */
    readonly action: TAction
    /** The resource type to check. */
    readonly resource: TResource
    /** Optional specific resource instance ID. */
    readonly resourceId?: string
    /** Optional scope for multi-tenant checks. */
    readonly scope?: TScope
    /**
     * The instance's own attributes, as `can()` would receive them.
     * SECURITY: omitting them evaluates the check against a resource that has none, so a rule conditioned on
     * `resource.attributes.*` cannot fire and the map may be more permissive than `can()`.
     */
    readonly attributes?: IamPrimitives.Attributes
  }
}
