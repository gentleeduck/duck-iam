export namespace IamClient {
  /**
   * Compound string key uniquely identifying a permission check result. Used
   * as keys in {@link PermissionMap}; formats:
   *  - `action:resource`
   *  - `action:resource:resourceId`
   *  - `@scope:action:resource`
   *  - `@scope:action:resource:resourceId`
   *
   * The `@` marks a scope, so a three-segment key is never ambiguous between a
   * scoped and an id-bearing check. Inside a segment `:` and a leading `@` are
   * escaped (`:` -> `\:`); see `iamBuildPermissionKey`.
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
    | `${TScope}:${TAction}:${TResource}`
    | `${TScope}:${TAction}:${TResource}:${string}`

  /**
   * Map from {@link PermissionKey} strings to boolean results. Returned by
   * `engine.permissions()` after batch-checking permissions for one subject.
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
   * What `engine.permissions()` actually returns: only the keys that were in the
   * batch. {@link PermissionMap} requires every combination, which no caller ever
   * has, so anything consuming a resolved map takes this instead. Lookups already
   * default a missing key to `false`, so the two behave identically at runtime.
   */
  export type PartialPermissionMap<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > = Partial<PermissionMap<TAction, TResource, TScope>>

  /**
   * Permission check descriptor for batch evaluation. Pass an array of these to
   * `engine.permissions()` or `access.checks()`.
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
  }
}
