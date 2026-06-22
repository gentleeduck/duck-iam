import type { IamAccessControl, IamDotPath, IamPrimitives } from '../types'
import { IamWhen } from './when'

/**
 * Fluent builder for constructing {@link IamAccessControl.IRule} objects in duck-iam.
 *
 * Rules are the atomic unit of an ABAC policy. Each rule declares an effect
 * (`allow` or `deny`), the actions and resources it covers, an optional scope
 * restriction, and an optional condition tree that must hold for the rule to
 * fire.
 *
 * Rules are collected into a {@link IamPolicyBuilder} and evaluated by the engine
 * using the policy's chosen conflict-resolution algorithm
 * (`allow-overrides`, `deny-overrides`, `first-match`, or `highest-priority`).
 *
 * @example
 * ```ts
 * import { iamDefineRule } from '@gentleduck/iam'
 *
 * const rule = iamDefineRule('post.update.owner')
 *   .allow()
 *   .desc('Authors may update their own posts')
 *   .priority(20)
 *   .on('update')
 *   .of('post')
 *   .when(w => w.isOwner())
 *   .build()
 * ```
 *
 * @template TAction         - Union of valid action strings (e.g. `'read' | 'write'`)
 * @template TResource       - Union of valid resource strings (e.g. `'post' | 'comment'`)
 * @template TScope          - Union of valid scope strings (e.g. `'org-1' | 'org-2'`)
 * @template TRole           - Union of valid role ID strings (e.g. `'viewer' | 'admin'`)
 * @template TContext        - Shape of the full evaluation context for typed dot-paths
 * @template TActiveResource - The narrowed resource selected via `.of()` (used by typed `resourceAttr`)
 */
export class IamRuleBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
  TRole extends string = string,
  TContext extends object = IamDotPath.IDefaultContext,
  TActiveResource extends string = string,
> {
  private _id: string
  private _effect: IamAccessControl.Effect = 'allow'
  private _description?: string
  private _priority = 10
  private _actions: (TAction | '*')[] = ['*']
  private _resources: (TResource | '*')[] = ['*']
  private _conditions: IamAccessControl.IConditionGroup = { all: [] }
  private _metadata?: IamPrimitives.Attributes
  private _scopeCondition?: IamAccessControl.ICondition

  constructor(id: string) {
    this._id = id
  }

  /**
   * Sets the rule effect to `allow`.
   *
   * This is the default effect - you only need to call this explicitly when
   * overriding a previous `.deny()` call on the same builder instance.
   *
   * @returns `this` for chaining
   */
  allow(): this {
    this._effect = 'allow'
    return this
  }

  /**
   * Sets the rule effect to `deny`.
   *
   * Deny rules take precedence over allow rules when the policy algorithm is
   * `deny-overrides`. Under `allow-overrides` a deny only wins if no allow
   * rule matches.
   *
   * @returns `this` for chaining
   */
  deny(): this {
    this._effect = 'deny'
    return this
  }

  /**
   * Attaches a human-readable description to the rule.
   *
   * Descriptions are stored on the {@link IamAccessControl.IRule} object and surfaced by the
   * engine's explain/debug output. They have no effect on evaluation.
   *
   * @param d - Description text
   * @returns `this` for chaining
   */
  desc(d: string): this {
    this._description = d
    return this
  }

  /**
   * Sets the rule's evaluation priority.
   *
   * Higher numbers are evaluated first. The default priority is `10`.
   * Priority matters when the policy algorithm is `highest-priority` - the
   * matching rule with the highest priority number wins.
   *
   * @param p - Priority value (higher = evaluated earlier)
   * @returns `this` for chaining
   */
  priority(p: number): this {
    this._priority = p
    return this
  }

  /**
   * Declares the actions this rule applies to.
   *
   * Pass `'*'` to match all actions. Accepts multiple arguments.
   *
   * @example
   * ```ts
   * iamDefineRule('post.read-write')
   *   .on('read', 'update')
   *   .of('post')
   * ```
   *
   * @param actions - One or more action strings, or `'*'` for all actions
   * @returns `this` for chaining
   */
  on(...actions: (TAction | '*')[]): this {
    this._actions = actions
    return this
  }

  /**
   * Declares the resources this rule applies to.
   *
   * Pass `'*'` to match all resources. Accepts multiple arguments.
   *
   * @example
   * ```ts
   * iamDefineRule('content.read')
   *   .on('read')
   *   .of('post', 'comment')
   * ```
   *
   * @param resources - One or more resource strings, or `'*'` for all resources
   * @returns `this` for chaining
   */
  of<R extends TResource | '*'>(...resources: R[]): IamRuleBuilder<TAction, TResource, TScope, TRole, TContext, R> {
    this._resources = resources
    /** : This cast to get intellisense working for the specified resource type */
    return this as unknown as IamRuleBuilder<TAction, TResource, TScope, TRole, TContext, R>
  }

  /**
   * Restricts this rule to one or more scopes.
   *
   * A scope typically represents a tenant, organization, or workspace.
   * IamWhen a scope is set, the engine only fires the rule when the request's
   * scope matches. Passing `'*'` is a no-op - use no scope restriction for
   * global rules instead.
   *
   * Scope conditions compose correctly with `.when()` and `.whenAny()`.
   *
   * @example
   * ```ts
   * iamDefineRule('org1.post.update')
   *   .allow()
   *   .on('update')
   *   .of('post')
   *   .forScope('org-1')
   * ```
   *
   * @param scopes - One or more scope strings to restrict this rule to
   * @returns `this` for chaining
   */
  forScope(...scopes: (TScope | '*')[]): this {
    const nonWild = scopes.filter((s): s is TScope => s !== '*')
    if (nonWild.length === 0) return this
    this._scopeCondition =
      nonWild.length === 1
        ? { field: 'scope', operator: 'eq', value: nonWild[0] }
        : { field: 'scope', operator: 'in', value: nonWild }
    return this
  }

  /**
   * Attaches an ALL-of condition group to the rule using a {@link IamWhen} builder.
   *
   * Every condition added inside the callback must hold (`AND` semantics) for
   * the rule to match. Composes with `.forScope()` - the scope check is
   * prepended to the condition list automatically at build time.
   *
   * @example
   * ```ts
   * iamDefineRule('expense.approve')
   *   .allow()
   *   .on('approve')
   *   .of('expense')
   *   .when(w => w
   *     .attr('department', 'eq', 'engineering')
   *     .resourceAttr('amount', 'lte', 10000)
   *   )
   * ```
   *
   * @param fn - Callback that receives a {@link IamWhen} builder and returns it after chaining conditions
   * @returns `this` for chaining
   */
  when(
    fn: (
      w: IamWhen<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    ) => IamWhen<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
  ): this {
    const w = new IamWhen<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
    fn(w)
    this._conditions = w.buildAll()
    return this
  }

  /**
   * Attaches an ANY-of condition group to the rule using a {@link IamWhen} builder.
   *
   * At least one condition added inside the callback must hold (`OR` semantics)
   * for the rule to match.
   *
   * @example
   * ```ts
   * iamDefineRule('post.manage')
   *   .allow()
   *   .on('update', 'delete')
   *   .of('post')
   *   .whenAny(w => w
   *     .isOwner()
   *     .attr('role', 'eq', 'admin')
   *   )
   * ```
   *
   * @param fn - Callback that receives a {@link IamWhen} builder and returns it after chaining conditions
   * @returns `this` for chaining
   */
  whenAny(
    fn: (
      w: IamWhen<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    ) => IamWhen<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
  ): this {
    const w = new IamWhen<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
    fn(w)
    this._conditions = w.buildAny()
    return this
  }

  /**
   * Attaches arbitrary metadata to the rule.
   *
   * Metadata is stored on the {@link IamAccessControl.IRule} object but is never used during
   * policy evaluation. Use it for audit logs, admin dashboards, or any
   * application-level bookkeeping.
   *
   * @param m - Key-value map of metadata attributes
   * @returns `this` for chaining
   */
  meta(m: IamPrimitives.Attributes): this {
    this._metadata = m
    return this
  }

  /**
   * Finalises the builder and returns a plain {@link IamAccessControl.IRule} object.
   *
   * Any scope condition set via `.forScope()` is merged into the condition
   * group here so that `.forScope()` and `.when()` / `.whenAny()` always
   * compose correctly regardless of call order.
   *
   * @returns A fully constructed, immutable {@link IamAccessControl.IRule}
   */
  build(): IamAccessControl.IRule<TAction, TResource> {
    let conditions = this._conditions

    if (this._scopeCondition) {
      conditions = {
        all: 'all' in conditions ? [this._scopeCondition, ...conditions.all] : [this._scopeCondition, conditions],
      }
    }

    return {
      id: this._id,
      effect: this._effect,
      description: this._description,
      priority: this._priority,
      actions: this._actions,
      resources: this._resources,
      conditions,
      metadata: this._metadata,
    }
  }
}

/**
 * Creates a new {@link IamRuleBuilder} for the given rule ID.
 *
 * Prefer this factory over instantiating `IamRuleBuilder` directly. IamWhen using
 * `createIam`, use `access.iamDefineRule()` instead to get type-safe
 * action, resource, and scope constraints.
 *
 * @example
 * ```ts
 * import { iamDefineRule } from '@gentleduck/iam'
 *
 * const rule = iamDefineRule('post.read')
 *   .allow()
 *   .on('read')
 *   .of('post')
 *   .build()
 * ```
 *
 * @param id - Unique identifier for this rule within its policy
 * @returns A new {@link IamRuleBuilder} instance
 *
 * @template TAction   - Union of valid action strings
 * @template TResource - Union of valid resource strings
 * @template TScope    - Union of valid scope strings
 * @template TRole     - Union of valid role ID strings
 * @template TContext  - Shape of the full evaluation context for typed dot-paths
 */
export const iamDefineRule = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
  TRole extends string = string,
  TContext extends object = IamDotPath.IDefaultContext,
>(
  id: string,
) => new IamRuleBuilder<TAction, TResource, TScope, TRole, TContext>(id)
