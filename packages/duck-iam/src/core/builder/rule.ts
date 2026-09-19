import type { AccessControl, DotPath, IamPrimitives } from '../types'
import type { IamValidate } from '../validate'
import { validateRuleShape } from '../validate/validate.libs'
import { iamChosenWhen, When } from './when'

/**
 * Chainable builder for an {@link AccessControl.IRule}: an effect, the actions and resources it covers,
 * an optional scope and a condition tree. Its `PolicyBuilder`'s algorithm resolves conflicts.
 *
 * @example
 * ```ts
 * import { defineRule } from '@gentleduck/iam'
 *
 * const rule = defineRule('post.update.owner')
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
export class RuleBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
  TRole extends string = string,
  TContext extends object = DotPath.IDefaultContext,
  TActiveResource extends string = string,
> {
  private _id: string
  private _effect: AccessControl.Effect = 'allow'
  private _description?: string
  private _priority = 10
  private _actions: (TAction | '*')[] = ['*']
  private _resources: (TResource | '*')[] = ['*']
  private _conditions: AccessControl.IConditionGroup = { all: [] }
  private _conditionsSet = false
  /**
   * Whether anything shaping what is granted was set; `desc`, `priority` and `meta` do not count.
   * SECURITY: the defaults are allow `*` on `*` unconditionally, so `build()` refuses while this is false.
   */
  private _grantShapeSet = false
  private _metadata?: IamPrimitives.Attributes
  private _scopeCondition?: AccessControl.ICondition

  constructor(id: string) {
    this._id = id
  }

  /**
   * ANDs a new group onto whatever `.when()` / `.whenAny()` already set.
   * SECURITY: replacing it would drop the earlier restriction and widen the rule.
   */
  private _addConditions(next: AccessControl.IConditionGroup): void {
    this._conditions = this._conditionsSet ? { all: [this._conditions, next] } : next
    this._conditionsSet = true
  }

  /** Sets the effect to `allow` (the default). Also the explicit opt-in that lets a broad `allow * *` rule build. */
  allow(): this {
    this._grantShapeSet = true
    this._effect = 'allow'
    return this
  }

  /**
   * Sets the effect to `deny`. It wins under `deny-overrides`; under `allow-overrides`, only if no allow matches.
   */
  deny(): this {
    this._grantShapeSet = true
    this._effect = 'deny'
    return this
  }

  /** Attaches a description, shown in explain output; no effect on evaluation. */
  desc(d: string): this {
    this._description = d
    return this
  }

  /** Sets the priority (default `10`). Under `first-match` and `highest-priority` the highest matching rule wins. */
  priority(p: number): this {
    this._priority = p
    return this
  }

  /**
   * Sets the actions this rule covers; `'*'` matches all.
   *
   * @example
   * ```ts
   * defineRule('post.read-write')
   *   .on('read', 'update')
   *   .of('post')
   * ```
   */
  on(...actions: (TAction | '*')[]): this {
    this._grantShapeSet = true
    this._actions = actions
    return this
  }

  /**
   * Sets the resources this rule covers; `'*'` matches all. Also types `resourceAttr` for them.
   *
   * @example
   * ```ts
   * defineRule('content.read')
   *   .on('read')
   *   .of('post', 'comment')
   * ```
   */
  of<R extends TResource | '*'>(...resources: R[]): RuleBuilder<TAction, TResource, TScope, TRole, TContext, R> {
    this._grantShapeSet = true
    this._resources = resources
    // Narrows TActiveResource so `resourceAttr` autocompletes the selected resources' attributes.
    return this as unknown as RuleBuilder<TAction, TResource, TScope, TRole, TContext, R>
  }

  /**
   * Restricts the rule to requests in one of `scopes` (e.g. tenants). `'*'` adds no condition; no scopes throws.
   * Composes with `.when()` / `.whenAny()` in either order.
   *
   * @example
   * ```ts
   * defineRule('org1.post.update')
   *   .allow()
   *   .on('update')
   *   .of('post')
   *   .forScope('org-1')
   * ```
   */
  forScope(...scopes: (TScope | '*')[]): this {
    // SECURITY: a runtime-empty `...tenantIds` must not become a global rule; `'*'` is how to say "every scope".
    if (scopes.length === 0) {
      throw new Error(
        `[@gentleduck/iam:builder] RuleBuilder.forScope("${this._id}") was called with no scopes. ` +
          'A scope restriction that names nothing would leave the rule global, which is the opposite ' +
          "of the intent. Pass at least one scope, or `'*'` if the rule really is unscoped.",
      )
    }
    // Counted even for `'*'`: `build()` refuses silence, and `.forScope('*')` is an explicit (if non-narrowing) choice.
    this._grantShapeSet = true
    const nonWild = scopes.filter((s): s is TScope => s !== '*')
    if (nonWild.length === 0) return this
    this._scopeCondition =
      nonWild.length === 1
        ? { field: 'scope', operator: 'eq', value: nonWild[0] }
        : { field: 'scope', operator: 'in', value: nonWild }
    return this
  }

  /**
   * Adds an AND group: every condition built in `fn` must hold. Repeated calls AND together.
   *
   * @example
   * ```ts
   * defineRule('expense.approve')
   *   .allow()
   *   .on('approve')
   *   .of('expense')
   *   .when(w => w
   *     .attr('department', 'eq', 'engineering')
   *     .resourceAttr('amount', 'lte', 10000)
   *   )
   * ```
   */
  when(
    fn: (
      w: When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    ) => When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
  ): this {
    const w = new When<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
    const group = iamChosenWhen(w, fn(w)).buildAll()
    // SECURITY: an empty `all` group matches every request (`.every` on `[]` is true), so it does not count
    // as configuring the grant. `whenAny` differs; see there.
    if (group.all.length > 0) this._grantShapeSet = true
    this._addConditions(group)
    return this
  }

  /**
   * Adds an OR group: at least one condition built in `fn` must hold. Repeated calls AND together.
   *
   * @example
   * ```ts
   * defineRule('post.manage')
   *   .allow()
   *   .on('update', 'delete')
   *   .of('post')
   *   .whenAny(w => w
   *     .isOwner()
   *     .attr('role', 'eq', 'admin')
   *   )
   * ```
   */
  whenAny(
    fn: (
      w: When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    ) => When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
  ): this {
    const w = new When<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
    // NOTE: counted even when empty, unlike `when`: `{any: []}` matches nothing (`.some` on `[]` is false),
    // so it fails closed, and an `any` list built from an empty collection legitimately means "nobody".
    this._grantShapeSet = true
    this._addConditions(iamChosenWhen(w, fn(w)).buildAny())
    return this
  }

  /** Attaches metadata for app bookkeeping (audit logs, dashboards); never used in evaluation. */
  meta(m: IamPrimitives.Attributes): this {
    this._metadata = m
    return this
  }

  /**
   * Returns the plain {@link AccessControl.IRule}, prepending any `.forScope()` condition to the group.
   *
   * @throws If the builder was never configured, or the rule fails validation
   */
  build(): AccessControl.IRule<TAction, TResource> {
    if (!this._grantShapeSet) {
      throw new Error(
        `[@gentleduck/iam:builder] RuleBuilder.build("${this._id}") was never configured - ` +
          'no effect, action, resource, scope or condition was set. The defaults are the broadest ' +
          'possible grant (allow * on *, unconditional), so this is refused rather than returned. ' +
          'Call `.allow()` if a broad grant is intended.',
      )
    }
    let conditions = this._conditions

    if (this._scopeCondition) {
      conditions = {
        all: 'all' in conditions ? [this._scopeCondition, ...conditions.all] : [this._scopeCondition, conditions],
      }
    }

    // Omit unset optional keys; see `PolicyBuilder.build`.
    const rule: AccessControl.IRule<TAction, TResource> = {
      id: this._id,
      effect: this._effect,
      ...(this._description === undefined ? {} : { description: this._description }),
      priority: this._priority,
      actions: this._actions,
      resources: this._resources,
      conditions,
      ...(this._metadata === undefined ? {} : { metadata: this._metadata }),
    }
    // Validate here too, so a rule handed straight to an adapter fails where the bug was written.
    const issues: IamValidate.IIssue[] = []
    validateRuleShape(rule, 'rule', issues)
    const errs = issues
      .filter((i) => i.type === 'error')
      .map((i) => `${i.code}${i.path ? ` at "${i.path}"` : ''}: ${i.message}`)
    if (errs.length > 0) {
      throw new Error(
        `[@gentleduck/iam:builder] RuleBuilder.build("${this._id}") rejected by validator - ${errs.join('; ')}`,
      )
    }
    return rule
  }
}

/**
 * Creates a {@link RuleBuilder}; `id` identifies the rule within its policy.
 * With `createIam`, use `access.defineRule()` for typed actions, resources and scopes.
 *
 * @example
 * ```ts
 * import { defineRule } from '@gentleduck/iam'
 *
 * const rule = defineRule('post.read')
 *   .allow()
 *   .on('read')
 *   .of('post')
 *   .build()
 * ```
 *
 * @template TAction   - Union of valid action strings
 * @template TResource - Union of valid resource strings
 * @template TScope    - Union of valid scope strings
 * @template TRole     - Union of valid role ID strings
 * @template TContext  - Shape of the full evaluation context for typed dot-paths
 */
export const defineRule = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
  TRole extends string = string,
  TContext extends object = DotPath.IDefaultContext,
>(
  id: string,
) => new RuleBuilder<TAction, TResource, TScope, TRole, TContext>(id)
