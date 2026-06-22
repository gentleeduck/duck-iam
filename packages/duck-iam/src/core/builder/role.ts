import type { IamAccessControl, IamDotPath, IamPrimitives } from '../types'
import { iamValidateRole } from '../validate'
import { IamWhen } from './when'

/**
 * Fluent builder for constructing {@link IamAccessControl.IRole} objects in duck-iam.
 *
 * Roles are the RBAC side of duck-iam. Each role holds a set of
 * action/resource permissions and an optional inheritance chain. At evaluation
 * time, `iamRolesToPolicy()` converts every role into ABAC rules that flow through
 * the same engine as hand-written policies, so RBAC and ABAC compose.
 *
 * Prefer the {@link iamDefineRole} factory (or `access.iamDefineRole()` for type-safe
 * variants) over instantiating `IamRoleBuilder` directly.
 *
 * @example
 * ```ts
 * import { iamDefineRole } from '@gentleduck/iam'
 *
 * const editor = iamDefineRole('editor')
 *   .name('Editor')
 *   .desc('Full write access to posts and comments')
 *   .inherits('viewer')
 *   .grant('create', 'post')
 *   .grant('update', 'post')
 *   .grant('delete', 'post')
 *   .grantCRUD('comment')
 *   .build()
 * ```
 *
 * @template TAction   - Union of valid action strings (e.g. `'read' | 'write'`)
 * @template TResource - Union of valid resource strings (e.g. `'post' | 'comment'`)
 * @template TRole       - Literal string type of the role ID (inferred by {@link iamDefineRole})
 * @template TScope    - Union of valid scope strings (e.g. `'org-1' | 'org-2'`)
 * @template TContext  - Shape of the full evaluation context for typed dot-paths
 */
export class IamRoleBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TContext extends object = IamDotPath.IDefaultContext,
> {
  private _id: TRole
  private _name: string
  private _description?: string
  private _permissions: IamAccessControl.IPermission<TAction, TResource, TScope>[] = []
  private _inherits: (TRole | (string & {}))[] = []
  private _scope?: TScope
  private _metadata?: IamPrimitives.Attributes

  constructor(id: TRole) {
    this._id = id
    this._name = id
  }

  /**
   * Sets a human-readable display name for the role.
   *
   * Defaults to the role ID if not called. Used in admin dashboards,
   * audit logs, and the engine's explain output.
   *
   * @param n - Display name (e.g. `'Content Editor'`)
   * @returns `this` for chaining
   */
  name(n: string): this {
    this._name = n
    return this
  }

  /**
   * Attaches a human-readable description to the role.
   *
   * Stored on the {@link IamAccessControl.IRole} object for documentation purposes.
   * Not used during policy evaluation.
   *
   * @param d - Description text
   * @returns `this` for chaining
   */
  desc(d: string): this {
    this._description = d
    return this
  }

  /**
   * Declares parent roles this role inherits from.
   *
   * The role receives all permissions from every listed parent, resolved
   * recursively. Multiple parents are supported. Inheritance cycles are
   * handled safely via a visited set - cycles are skipped rather than
   * causing infinite recursion.
   *
   * Note: inherited permissions cannot be selectively removed. To restrict
   * access below what a parent grants, use an ABAC deny policy instead.
   *
   * @example
   * ```ts
   * // Single parent
   * iamDefineRole('editor').inherits('viewer')
   *
   * // Multiple parents
   * iamDefineRole('moderator').inherits('viewer', 'commenter')
   * ```
   *
   * @param roleIds - IDs of the parent roles to inherit from
   * @returns `this` for chaining
   */
  inherits(...roleIds: (TRole | (string & {}))[]): this {
    this._inherits = roleIds
    return this
  }

  /**
   * Sets a default scope that applies to every permission in this role.
   *
   * IamWhen `iamRolesToPolicy()` converts this role, each generated rule gets an
   * additional condition `scope eq "<s>"`. The permission only fires when the
   * request's scope matches.
   *
   * To scope individual permissions rather than the entire role, use
   * {@link grantScoped} instead.
   *
   * @example
   * ```ts
   * const orgEditor = iamDefineRole('org-editor')
   *   .scope('org-1')
   *   .grant('create', 'post')
   *   .grant('update', 'post')
   *   .build()
   * ```
   *
   * @param s - The scope string to restrict all permissions to
   * @returns `this` for chaining
   */
  scope(s: TScope): this {
    this._scope = s
    return this
  }

  /**
   * Grants a single unconditional permission on an action/resource pair.
   *
   * Pass `'*'` for either argument to match all actions or all resources.
   * Pass an optional `scope` to restrict this permission to a specific scope
   * (e.g. a tenant or workspace). Without a scope the permission is global.
   *
   * @example
   * ```ts
   * iamDefineRole('viewer')
   *   .grant('read', 'post')
   *   .grant('read', 'comment')
   *
   * // With permission-level scope
   * iamDefineRole('hybrid')
   *   .grant('read', 'post')                     // global
   *   .grant('update', 'post', 'org-1')           // org-1 only
   *   .grant('create', 'comment', 'org-2')        // org-2 only
   * ```
   *
   * @param action   - The action to permit, or `'*'` for all actions
   * @param resource - The resource to permit, or `'*'` for all resources
   * @param scope    - Optional scope to restrict this permission to
   * @returns `this` for chaining
   */
  grant(action: TAction | '*', resource: TResource | '*', scope?: TScope): this {
    this._permissions.push(scope ? { action, resource, scope } : { action, resource })
    return this
  }

  /**
   * Grants a single permission restricted to a specific scope.
   *
   * Unlike {@link scope}, which scopes the entire role, `grantScoped` lets
   * you mix global and scoped permissions within the same role.
   *
   * @example
   * ```ts
   * iamDefineRole('hybrid')
   *   .grant('read', 'post')                    // global
   *   .grantScoped('org-1', 'update', 'post')   // org-1 only
   *   .grantScoped('org-2', 'create', 'comment') // org-2 only
   * ```
   *
   * @param scope    - The scope this permission is restricted to
   * @param action   - The action to permit, or `'*'` for all actions
   * @param resource - The resource to permit, or `'*'` for all resources
   * @returns `this` for chaining
   */
  grantScoped(scope: TScope, action: TAction | '*', resource: TResource | '*'): this {
    this._permissions.push({ action, resource, scope })
    return this
  }

  /**
   * Grants a permission that only applies when a condition holds.
   *
   * The callback receives a {@link IamWhen} builder. All conditions added inside
   * the callback must hold simultaneously (`AND` semantics). Use
   * `w.isOwner()` as a shorthand for checking `resource.attributes.ownerId eq $subject.id`.
   *
   * @example
   * ```ts
   * iamDefineRole('author')
   *   .grant('read', 'post')
   *   .grantWhen('update', 'post', w => w.isOwner())
   *   .grantWhen('delete', 'post', w => w.isOwner())
   *
   * // Complex condition
   * iamDefineRole('team-lead')
   *   .grantWhen('approve', 'expense', w => w
   *     .attr('department', 'eq', 'engineering')
   *     .resourceAttr('amount', 'lte', 10000)
   *   )
   * ```
   *
   * @param action   - The action to permit conditionally
   * @param resource - The resource to permit conditionally
   * @param fn       - Callback that builds the condition using a {@link IamWhen} builder
   * @returns `this` for chaining
   */
  grantWhen<R extends TResource | '*'>(
    action: TAction | '*',
    resource: R,
    fn: (
      w: IamWhen<TAction, TResource, TRole, TScope, TContext, R>,
    ) => IamWhen<TAction, TResource, TRole, TScope, TContext, R>,
  ): this {
    const w = new IamWhen<TAction, TResource, TRole, TScope, TContext, R>()
    fn(w)
    this._permissions.push({ action, resource, conditions: w.buildAll() })
    return this
  }

  /**
   * Grants all actions (`'*'`) on a resource.
   *
   * Use `grantAll('*')` to grant unrestricted access to everything (typical
   * for a super-admin role). For a more explicit alternative that only covers
   * standard CRUD, see {@link grantCRUD}.
   *
   * @example
   * ```ts
   * iamDefineRole('super-admin').grantAll('*')  // all actions, all resources
   * iamDefineRole('post-admin').grantAll('post') // all actions on posts only
   * ```
   *
   * @param resource - The resource to grant all actions on, or `'*'` for all resources
   * @returns `this` for chaining
   */
  grantAll(resource: TResource | '*'): this {
    return this.grant('*', resource)
  }

  /**
   * Grants `read` access to one or more resources.
   *
   * Accepts multiple resource arguments. Equivalent to calling
   * `.grant('read', resource)` for each.
   *
   * @example
   * ```ts
   * iamDefineRole('auditor')
   *   .grantRead('post', 'comment', 'user', 'audit-log')
   * ```
   *
   * @param resources - One or more resource strings to grant read access on
   * @returns `this` for chaining
   */
  grantRead(...resources: (TResource | '*')[]): this {
    for (const r of resources) this.grant('read' as TAction | '*', r)
    return this
  }

  /**
   * Grants `create`, `read`, `update`, and `delete` on a resource.
   *
   * More explicit than {@link grantAll} - does not include custom actions
   * like `publish` or `archive`. Equivalent to four separate `.grant()` calls.
   *
   * @example
   * ```ts
   * iamDefineRole('content-manager')
   *   .grantCRUD('post')
   *   .grantCRUD('comment')
   * ```
   *
   * @param resource - The resource to grant CRUD access on
   * @returns `this` for chaining
   */
  grantCRUD(resource: TResource | '*'): this {
    for (const a of ['create', 'read', 'update', 'delete'] as (TAction | '*')[]) {
      this.grant(a, resource)
    }
    return this
  }

  /**
   * Attaches arbitrary metadata to the role.
   *
   * Metadata is stored on the {@link IamAccessControl.IRole} object but is never consulted
   * during policy evaluation. Use it for admin dashboards, audit logs,
   * UI labels, or any other application-level bookkeeping.
   *
   * @example
   * ```ts
   * iamDefineRole('beta-tester')
   *   .meta({ createdBy: 'system', tier: 'beta', maxSeats: 10 })
   *   .grant('read', 'beta-feature')
   * ```
   *
   * @param m - Key-value map of metadata attributes
   * @returns `this` for chaining
   */
  meta(m: IamPrimitives.Attributes): this {
    this._metadata = m
    return this
  }

  /**
   * Finalises the builder and returns a plain {@link IamAccessControl.IRole} object.
   *
   * The returned object is a plain data record with no builder methods.
   * Pass it to `engine.admin.saveRole()` or `access.()`.
   *
   * @returns A fully constructed {@link IamAccessControl.IRole}
   */
  build(): IamAccessControl.IRole<TAction, TResource, TRole, TScope> {
    const role: IamAccessControl.IRole<TAction, TResource, TRole, TScope> = {
      id: this._id,
      name: this._name,
      description: this._description,
      permissions: this._permissions,
      inherits: this._inherits.length > 0 ? this._inherits : undefined,
      scope: this._scope,
      metadata: this._metadata,
    }
    // IamValidate at build time so callers wiring the adapter directly
    // still see the failure where the bug was introduced.
    const result = iamValidateRole(role)
    if (!result.valid) {
      const errs = result.issues
        .filter((i) => i.type === 'error')
        .map((i) => (i.path ? `${i.code} at "${i.path}"` : i.code))
      throw new Error(`[@gentleduck/iam:builder] IamRoleBuilder.build(): role rejected by validator - ${errs.join('; ')}`)
    }
    return role
  }
}

/**
 * Creates a new {@link IamRoleBuilder} for the given role ID.
 *
 * The role ID is preserved as a literal type (`TId`) so that references to
 * it in `.inherits()` calls and adapter lookups remain type-safe when using
 * `createIam`.
 *
 * For type-safe action, resource, and scope constraints, use
 * `access.iamDefineRole()` returned by `createIam()` instead.
 *
 * @example
 * ```ts
 * import { iamDefineRole } from '@gentleduck/iam'
 *
 * const viewer = iamDefineRole('viewer')
 *   .name('Viewer')
 *   .desc('Read-only access to published content')
 *   .grant('read', 'post')
 *   .grant('read', 'comment')
 *   .build()
 * ```
 *
 * @param id - Unique identifier for this role
 * @returns A new {@link IamRoleBuilder} instance typed to the given ID
 *
 * @template TId       - Inferred literal type of the role ID
 * @template TAction   - Union of valid action strings (defaults to `string`)
 * @template TResource - Union of valid resource strings (defaults to `string`)
 * @template TScope    - Union of valid scope strings (defaults to `string`)
 * @template TContext  - Shape of the full evaluation context for typed dot-paths
 */
export const iamDefineRole = <
  const TRole extends string,
  const TAction extends string = string,
  const TResource extends string = string,
  const TScope extends string = string,
  TContext extends object = IamDotPath.IDefaultContext,
>(
  id: TRole,
) => new IamRoleBuilder<TAction, TResource, TRole, TScope, TContext>(id)
