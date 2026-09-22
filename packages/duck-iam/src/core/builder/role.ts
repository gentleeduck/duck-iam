import type { AccessControl, DotPath, IamPrimitives } from '../types'
import { validateRole } from '../validate'
import { iamChosenWhen, When } from './when'

/**
 * The four verbs {@link RoleBuilder.grantCRUD} emits. Spread into a config's actions
 * (`[...IAM_CRUD_ACTIONS, 'publish']`) to keep `grantCRUD` callable.
 */
export const IAM_CRUD_ACTIONS = ['create', 'read', 'update', 'delete'] as const

/** One of the four verbs in {@link IAM_CRUD_ACTIONS}. */
export type IamCrudAction = (typeof IAM_CRUD_ACTIONS)[number]

/**
 * Chainable builder for an {@link AccessControl.IRole}: permissions plus optional parent roles.
 * `rolesToPolicy()` turns roles into ABAC rules, so RBAC and ABAC share one engine.
 *
 * @example
 * ```ts
 * import { defineRole } from '@gentleduck/iam'
 *
 * const editor = defineRole('editor')
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
 * @template TRole     - Literal string type of the role ID (inferred by {@link defineRole})
 * @template TScope    - Union of valid scope strings (e.g. `'org-1' | 'org-2'`)
 * @template TContext  - Shape of the full evaluation context for typed dot-paths
 */
export class RoleBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TContext extends object = DotPath.IDefaultContext,
> {
  private _id: TRole
  private _name: string
  private _description?: string
  private _permissions: AccessControl.IPermission<TAction, TResource, TScope>[] = []
  private _inherits: (TRole | (string & {}))[] = []
  private _scope?: TScope
  private _metadata?: IamPrimitives.Attributes

  constructor(id: TRole) {
    this._id = id
    this._name = id
  }

  /** Sets the display name; defaults to the role ID. */
  name(n: string): this {
    this._name = n
    return this
  }

  /** Attaches a description; not used in evaluation. */
  desc(d: string): this {
    this._description = d
    return this
  }

  /**
   * Declares parent roles to inherit permissions from, recursively. To grant less than a parent, use a deny policy.
   * WARN: replaces earlier parents rather than appending like `grant*`; a bare `.inherits()` clears them.
   *
   * @example
   * ```ts
   * defineRole('editor').inherits('viewer')
   * defineRole('moderator').inherits('viewer', 'commenter')
   * ```
   */
  inherits(...roleIds: (TRole | (string & {}))[]): this {
    this._inherits = roleIds
    return this
  }

  /**
   * Scopes every permission in the role; under `scopeMode: 'hierarchical'`, `'org-1'` also covers `'org-1.team-a'`.
   * To scope a single permission, use {@link RoleBuilder.grantScoped}.
   *
   * @example
   * ```ts
   * const orgEditor = defineRole('org-editor')
   *   .scope('org-1')
   *   .grant('create', 'post')
   *   .grant('update', 'post')
   *   .build()
   * ```
   */
  scope(s: TScope): this {
    this._scope = s
    return this
  }

  /**
   * Grants an unconditional permission (`'*'` matches all); global unless `scope` is given.
   *
   * @example
   * ```ts
   * defineRole('hybrid')
   *   .grant('read', 'post')             // global
   *   .grant('update', 'post', 'org-1')  // org-1 only
   * ```
   */
  grant(action: TAction | '*', resource: TResource | '*', scope?: TScope): this {
    // NOTE: `!== undefined`, not truthiness, so an empty scope reaches the validator instead of becoming global.
    this._permissions.push(scope !== undefined ? { action, resource, scope } : { action, resource })
    return this
  }

  /**
   * Grants a permission in one scope, so a role can mix global and scoped permissions (unlike {@link RoleBuilder.scope}).
   *
   * @example
   * ```ts
   * defineRole('hybrid')
   *   .grant('read', 'post')                    // global
   *   .grantScoped('org-1', 'update', 'post')   // org-1 only
   *   .grantScoped('org-2', 'create', 'comment') // org-2 only
   * ```
   */
  grantScoped(scope: TScope, action: TAction | '*', resource: TResource | '*'): this {
    this._permissions.push({ action, resource, scope })
    return this
  }

  /**
   * Grants a permission that applies only when every condition built in `fn` holds.
   *
   * @example
   * ```ts
   * defineRole('author')
   *   .grant('read', 'post')
   *   .grantWhen('update', 'post', w => w.isOwner())
   *
   * defineRole('team-lead')
   *   .grantWhen('approve', 'expense', w => w
   *     .attr('department', 'eq', 'engineering')
   *     .resourceAttr('amount', 'lte', 10000)
   *   )
   * ```
   */
  grantWhen<R extends TResource | '*'>(
    action: TAction | '*',
    resource: R,
    fn: (
      w: When<TAction, TResource, TRole, TScope, TContext, R>,
    ) => When<TAction, TResource, TRole, TScope, TContext, R>,
  ): this {
    const w = new When<TAction, TResource, TRole, TScope, TContext, R>()
    this._permissions.push({ action, resource, conditions: iamChosenWhen(w, fn(w)).buildAll() })
    return this
  }

  /**
   * Grants every action (`'*'`) on `resource`. For only the four CRUD verbs, see {@link RoleBuilder.grantCRUD}.
   *
   * @example
   * ```ts
   * defineRole('super-admin').grantAll('*')  // all actions, all resources
   * defineRole('post-admin').grantAll('post') // all actions on posts only
   * ```
   */
  grantAll(resource: TResource | '*'): this {
    return this.grant('*', resource)
  }

  /**
   * Grants `read` on each resource.
   * NOTE: only callable when `TAction` includes `'read'`, so a grant no request could match fails to compile.
   *
   * @example
   * ```ts
   * defineRole('auditor')
   *   .grantRead('post', 'comment', 'user', 'audit-log')
   * ```
   */
  grantRead(...resources: ('read' extends TAction ? TResource | '*' : never)[]): this {
    // The parameter gate proves `'read' extends TAction`; TypeScript cannot carry that into a generic body.
    const action: TAction | '*' = 'read' as TAction
    for (const r of resources) this.grant(action, r)
    return this
  }

  /**
   * Grants `create`, `read`, `update` and `delete` on `resource`; unlike {@link RoleBuilder.grantAll}, no custom actions.
   * NOTE: only callable when `TAction` includes all four; see {@link RoleBuilder.grantRead}.
   *
   * @example
   * ```ts
   * defineRole('content-manager')
   *   .grantCRUD('post')
   *   .grantCRUD('comment')
   * ```
   */
  grantCRUD(resource: IamCrudAction extends TAction ? TResource | '*' : never): this {
    for (const a of IAM_CRUD_ACTIONS) {
      const action: TAction | '*' = a as TAction
      this.grant(action, resource)
    }
    return this
  }

  /**
   * Attaches metadata for app bookkeeping (dashboards, audit logs, UI labels); never used in evaluation.
   *
   * @example
   * ```ts
   * defineRole('beta-tester')
   *   .meta({ createdBy: 'system', tier: 'beta', maxSeats: 10 })
   *   .grant('read', 'beta-feature')
   * ```
   */
  meta(m: IamPrimitives.Attributes): this {
    this._metadata = m
    return this
  }

  /**
   * Returns the plain {@link AccessControl.IRole}, ready for `engine.admin.saveRole()` or an adapter's `saveRole()`.
   *
   * @throws If the role fails validation
   */
  build(): AccessControl.IRole<TAction, TResource, TRole, TScope> {
    // Omit unset optional keys; see `PolicyBuilder.build`.
    const role: AccessControl.IRole<TAction, TResource, TRole, TScope> = {
      id: this._id,
      name: this._name,
      ...(this._description === undefined ? {} : { description: this._description }),
      permissions: [...this._permissions],
      ...(this._inherits.length === 0 ? {} : { inherits: [...this._inherits] }),
      ...(this._scope === undefined ? {} : { scope: this._scope }),
      ...(this._metadata === undefined ? {} : { metadata: this._metadata }),
    }
    // Validate here too, so a role handed straight to an adapter fails where the bug was written.
    const result = validateRole(role)
    if (!result.valid) {
      const errs = result.issues
        .filter((i) => i.type === 'error')
        .map((i) => (i.path ? `${i.code} at "${i.path}"` : i.code))
      throw new Error(`[@gentleduck/iam:builder] RoleBuilder.build(): role rejected by validator - ${errs.join('; ')}`)
    }
    return role
  }
}

/**
 * Creates a {@link RoleBuilder}, keeping the role ID as a literal type.
 * With `createIam`, use `access.defineRole()` for typed actions, resources and scopes.
 *
 * @example
 * ```ts
 * import { defineRole } from '@gentleduck/iam'
 *
 * const viewer = defineRole('viewer')
 *   .name('Viewer')
 *   .desc('Read-only access to published content')
 *   .grant('read', 'post')
 *   .grant('read', 'comment')
 *   .build()
 * ```
 *
 * @template TRole    - Inferred literal type of the role ID
 * @template TAction   - Union of valid action strings (defaults to `string`)
 * @template TResource - Union of valid resource strings (defaults to `string`)
 * @template TScope    - Union of valid scope strings (defaults to `string`)
 * @template TContext  - Shape of the full evaluation context for typed dot-paths
 */
export const defineRole = <
  const TRole extends string,
  const TAction extends string = string,
  const TResource extends string = string,
  const TScope extends string = string,
  TContext extends object = DotPath.IDefaultContext,
>(
  id: TRole,
) => new RoleBuilder<TAction, TResource, TRole, TScope, TContext>(id)
