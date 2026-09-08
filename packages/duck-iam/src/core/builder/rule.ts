import type { AccessControl, DotPath, IamPrimitives } from '../types'
import type { IamValidate } from '../validate'
import { validateRuleShape } from '../validate/validate.libs'
import { iamChosenWhen, When } from './when'

/**
 * Fluent builder for constructing {@link AccessControl.IRule} objects in duck-iam.
 *
 * Rules are the atomic unit of an ABAC policy. Each rule declares an effect
 * (`allow` or `deny`), the actions and resources it covers, an optional scope
 * restriction, and an optional condition tree that must hold for the rule to
 * fire.
 *
 * Rules are collected into a {@link PolicyBuilder} and evaluated by the engine
 * using the policy's chosen conflict-resolution algorithm
 * (`allow-overrides`, `deny-overrides`, `first-match`, or `highest-priority`).
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
   * Whether anything that shapes *what is granted* has been said. `desc`,
   * `priority` and `meta` deliberately do not count: they annotate a rule, they
   * do not narrow it.
   *
   * The defaults are the broadest possible grant - `allow` on `['*']` x `['*']`
   * with `{all:[]}` conditions, which evaluates true - so a builder nobody
   * configured is not an empty rule, it is allow-everything. `build()` refuses
   * that rather than returning it, which is what `PolicyBuilder.rule()` has
   * always claimed happens. A *deliberate* broad grant still builds: say
   * `.allow()` and the flag is set.
   */
  private _grantShapeSet = false
  private _metadata?: IamPrimitives.Attributes
  private _scopeCondition?: AccessControl.ICondition

  constructor(id: string) {
    this._id = id
  }

  /**
   * ANDs a new group onto whatever `.when()` / `.whenAny()` already set.
   *
   * Replacing instead would let a second call silently drop the first
   * restriction, turning a narrow rule into a broad one.
   */
  private _addConditions(next: AccessControl.IConditionGroup): void {
    this._conditions = this._conditionsSet ? { all: [this._conditions, next] } : next
    this._conditionsSet = true
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
    this._grantShapeSet = true
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
    this._grantShapeSet = true
    this._effect = 'deny'
    return this
  }

  /**
   * Attaches a human-readable description to the rule.
   *
   * Descriptions are stored on the {@link AccessControl.IRule} object and surfaced by the
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
   * defineRule('post.read-write')
   *   .on('read', 'update')
   *   .of('post')
   * ```
   *
   * @param actions - One or more action strings, or `'*'` for all actions
   * @returns `this` for chaining
   */
  on(...actions: (TAction | '*')[]): this {
    this._grantShapeSet = true
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
   * defineRule('content.read')
   *   .on('read')
   *   .of('post', 'comment')
   * ```
   *
   * @param resources - One or more resource strings, or `'*'` for all resources
   * @returns `this` for chaining
   */
  of<R extends TResource | '*'>(...resources: R[]): RuleBuilder<TAction, TResource, TScope, TRole, TContext, R> {
    this._grantShapeSet = true
    this._resources = resources
    // Narrows TActiveResource so `.when(w => w.resourceAttr(...))` autocompletes
    // the attributes of the resource(s) just selected.
    return this as unknown as RuleBuilder<TAction, TResource, TScope, TRole, TContext, R>
  }

  /**
   * Restricts this rule to one or more scopes.
   *
   * A scope typically represents a tenant, organization, or workspace.
   * When a scope is set, the engine only fires the rule when the request's
   * scope matches. Passing `'*'` is a no-op - use no scope restriction for
   * global rules instead.
   *
   * Scope conditions compose correctly with `.when()` and `.whenAny()`.
   *
   * @example
   * ```ts
   * defineRule('org1.post.update')
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
    // A scope restriction that names no scope is always a call-site bug, and
    // the shape that gets here in practice is `.forScope(...tenantIds)` with a
    // list that came back empty. Reading that as "every scope" is the fail-open
    // reading: the author asked for a restriction and would silently get a
    // global rule. `'*'` is how "every scope" is said out loud.
    if (scopes.length === 0) {
      throw new Error(
        `[@gentleduck/iam:builder] RuleBuilder.forScope("${this._id}") was called with no scopes. ` +
          'A scope restriction that names nothing would leave the rule global, which is the opposite ' +
          "of the intent. Pass at least one scope, or `'*'` if the rule really is unscoped.",
      )
    }
    // Counted even when every scope is `'*'`. The refusal in `build()` is aimed
    // at *silence* - a callback that configured nothing - and `.forScope('*')`
    // is an explicit statement about scope, so it is not silence. It narrows
    // nothing, which is why the wildcard still produces no condition below.
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
   * Attaches an ALL-of condition group to the rule using a {@link When} builder.
   *
   * Every condition added inside the callback must hold (`AND` semantics) for
   * the rule to match. Composes with `.forScope()` - the scope check is
   * prepended to the condition list automatically at build time. Calling
   * `.when()` / `.whenAny()` again ANDs the new group onto the existing one.
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
   *
   * @param fn - Callback that receives a {@link When} builder and returns it after chaining conditions
   * @returns `this` for chaining
   */
  when(
    fn: (
      w: When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    ) => When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
  ): this {
    const w = new When<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
    const group = iamChosenWhen(w, fn(w)).buildAll()
    // Only a callback that actually added a condition counts as configuring the
    // grant. An empty `all` group is not a narrow rule, it is the broadest one:
    // `evalConditionGroup` runs `.every` over it, and `.every` on an empty array
    // is `true`, so `{all: []}` matches every request. Counting it would let
    // `.when(w => w)` build the same allow-everything rule `build()` refuses.
    // `whenAny` deliberately does not do this - see its own note.
    if (group.all.length > 0) this._grantShapeSet = true
    this._addConditions(group)
    return this
  }

  /**
   * Attaches an ANY-of condition group to the rule using a {@link When} builder.
   *
   * At least one condition added inside the callback must hold (`OR` semantics)
   * for the rule to match. A second `.when()` / `.whenAny()` call ANDs its
   * group onto this one rather than replacing it.
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
   *
   * @param fn - Callback that receives a {@link When} builder and returns it after chaining conditions
   * @returns `this` for chaining
   */
  whenAny(
    fn: (
      w: When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    ) => When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
  ): this {
    const w = new When<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
    // Counted unconditionally, unlike `when`. An empty `any` group fails closed
    // where an empty `all` group fails open: `.some` on an empty array is
    // `false`, so `{any: []}` matches nothing and the rule can never grant.
    // Building an `any` list from a collection that turns out to be empty is a
    // legitimate way to say "nobody", so there is nothing to refuse here.
    this._grantShapeSet = true
    this._addConditions(iamChosenWhen(w, fn(w)).buildAny())
    return this
  }

  /**
   * Attaches arbitrary metadata to the rule.
   *
   * Metadata is stored on the {@link AccessControl.IRule} object but is never used during
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
   * Finalises the builder and returns a plain {@link AccessControl.IRule} object.
   *
   * Any scope condition set via `.forScope()` is merged into the condition
   * group here so that `.forScope()` and `.when()` / `.whenAny()` always
   * compose correctly regardless of call order.
   *
   * @throws If the resulting rule fails validation
   * @returns A fully constructed, immutable {@link AccessControl.IRule}
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

    // See `PolicyBuilder.build`: an optional key set to `undefined` is a shape
    // difference between backends, not a value.
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
    // Validate at build time, like RoleBuilder and PolicyBuilder do, so a rule
    // handed straight to an adapter still fails where the bug was introduced.
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
 * Creates a new {@link RuleBuilder} for the given rule ID.
 *
 * Prefer this factory over instantiating `RuleBuilder` directly. When using
 * `createIam`, use `access.defineRule()` instead to get type-safe
 * action, resource, and scope constraints.
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
 * @param id - Unique identifier for this rule within its policy
 * @returns A new {@link RuleBuilder} instance
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
