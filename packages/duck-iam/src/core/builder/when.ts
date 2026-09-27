import { throwIamError } from '../errors'
import type { AccessControl, DotPath, IamPrimitives } from '../types'

/**
 * Shape of the callback passed to `When.and`/`.or`/`.not`, `RuleBuilder.when`/`.whenAny` and
 * `RoleBuilder.grantWhen`: takes the nested builder and returns the one to read conditions from.
 */
export type WhenGroupFn<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TContext extends object = DotPath.IDefaultContext,
  TActiveResource extends string = string,
> = (
  w: When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
) => When<TAction, TResource, TRole, TScope, TContext, TActiveResource>

/**
 * Chainable condition builder passed to `RuleBuilder.when`, `RuleBuilder.whenAny` and
 * `RoleBuilder.grantWhen`. `buildAll`/`buildAny`/`buildNone` emit the AND/OR/NOT group.
 *
 * @example
 * ```ts
 * // Inside a rule
 * defineRule('expense.approve')
 *   .allow()
 *   .on('approve').of('expense')
 *   .when(w => w
 *     .attr('department', 'eq', 'engineering')
 *     .resourceAttr('amount', 'lte', 10_000)
 *   )
 *
 * // Nested OR inside an AND
 * defineRule('post.edit')
 *   .allow()
 *   .on('update').of('post')
 *   .when(w => w
 *     .or(o => o.isOwner().role('admin'))
 *     .env('time', 'gte', 9)
 *   )
 * ```
 *
 * @template TAction         - Union of valid action strings
 * @template TResource       - Union of valid resource strings
 * @template TRole           - Union of valid role ID strings
 * @template TScope          - Union of valid scope strings
 * @template TContext        - Shape of the full evaluation context for typed dot-paths
 * @template TActiveResource - Resource narrowed by the parent `RuleBuilder.of()` (typed `resourceAttr`)
 */
export class When<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TContext extends object = DotPath.IDefaultContext,
  TActiveResource extends string = string,
> {
  private _items: Array<AccessControl.ICondition | AccessControl.IConditionGroup> = []

  /**
   * Appends a raw condition. `field` is a typed dot-path into `TContext`; `value` is inferred from it.
   * Omit `value` for `exists`.
   *
   * @example
   * ```ts
   * w.check('subject.attributes.status', 'eq', 'banned')   // OK
   * w.check('resource.attributes.status', 'eq', 'deleted') // ERROR if 'deleted' not in type
   * w.check('subject.attributes.age', 'eq', 30)            // ERROR if 'age' not in type
   * ```
   */
  check<P extends DotPath.FlexibleDotPaths<TContext>>(
    field: P,
    op: AccessControl.Operator,
    value?: DotPath.FieldValue<TContext, P> | DotPath.FlexibleDollarPaths<TContext>,
  ): this {
    this._items.push({ field, operator: op, value })
    return this
  }

  /** Asserts `field == value`. */
  eq<P extends DotPath.FlexibleDotPaths<TContext>>(
    field: P,
    value: DotPath.FieldValue<TContext, P> | DotPath.FlexibleDollarPaths<TContext>,
  ): this {
    this._items.push({ field, operator: 'eq', value })
    return this
  }

  /** Asserts `field != value`. */
  neq<P extends DotPath.FlexibleDotPaths<TContext>>(
    field: P,
    value: DotPath.FieldValue<TContext, P> | DotPath.FlexibleDollarPaths<TContext>,
  ): this {
    this._items.push({ field, operator: 'neq', value })
    return this
  }

  /** Asserts `field` is one of `values`. An empty list matches nothing. */
  in<P extends DotPath.FlexibleDotPaths<TContext>>(
    field: P,
    values: Array<DotPath.FieldValue<TContext, P> | DotPath.FlexibleDollarPaths<TContext>>,
  ): this {
    this._items.push({ field, operator: 'in', value: values as IamPrimitives.AttributeValue })
    return this
  }

  /** Asserts the array at `field` contains `value`, e.g. `w.contains('subject.roles', 'admin')`. */
  contains<P extends DotPath.FlexibleDotPaths<TContext>>(field: P, value: string): this {
    this._items.push({ field, operator: 'contains', value })
    return this
  }

  /** Asserts `field` is defined and non-null. */
  exists<P extends DotPath.FlexibleDotPaths<TContext>>(field: P): this {
    this._items.push({ field, operator: 'exists' })
    return this
  }

  /** Asserts `field > value`. */
  gt<P extends DotPath.FlexibleDotPaths<TContext>>(field: P, value: number): this {
    this._items.push({ field, operator: 'gt', value })
    return this
  }

  /** Asserts `field >= value`. */
  gte<P extends DotPath.FlexibleDotPaths<TContext>>(field: P, value: number): this {
    this._items.push({ field, operator: 'gte', value })
    return this
  }

  /** Asserts `field < value`. */
  lt<P extends DotPath.FlexibleDotPaths<TContext>>(field: P, value: number): this {
    this._items.push({ field, operator: 'lt', value })
    return this
  }

  /** Asserts `field <= value`. */
  lte<P extends DotPath.FlexibleDotPaths<TContext>>(field: P, value: number): this {
    this._items.push({ field, operator: 'lte', value })
    return this
  }

  /** Asserts `field` matches the regular expression source `regex`. */
  matches<P extends DotPath.FlexibleDotPaths<TContext>>(field: P, regex: string): this {
    this._items.push({ field, operator: 'matches', value: regex })
    return this
  }

  /** Asserts the subject holds `roleId`; same as `w.contains('subject.roles', roleId)`. */
  role(roleId: TRole): this {
    this._items.push({ field: 'subject.roles', operator: 'contains', value: roleId })
    return this
  }

  /** Asserts the subject holds at least one of `roleIds`. Throws when called with none. */
  roles(...roleIds: TRole[]): this {
    assertNonEmptyList('roles', roleIds)
    this._items.push({ field: 'subject.roles', operator: 'in', value: [...roleIds] })
    return this
  }

  /** Asserts the request scope is `id`. */
  scope(id: TScope): this {
    this._items.push({ field: 'scope', operator: 'eq', value: id })
    return this
  }

  /** Asserts the request scope is one of `ids`. Throws when called with none. */
  scopes(...ids: TScope[]): this {
    assertNonEmptyList('scopes', ids)
    this._items.push({ field: 'scope', operator: 'in', value: [...ids] })
    return this
  }

  /**
   * Asserts the subject owns the resource: `ownerField` equals `$subject.id`, resolved at evaluation time.
   *
   * @example
   * ```ts
   * w.isOwner() // resource.attributes.ownerId
   * w.isOwner('resource.attributes.createdBy')
   * ```
   */
  isOwner(
    ownerField: DotPath.FlexibleDotPaths<TContext> = 'resource.attributes.ownerId' as DotPath.FlexibleDotPaths<TContext>,
  ): this {
    this._items.push({ field: ownerField, operator: 'eq', value: '$subject.id' })
    return this
  }

  /** Asserts `resource.type` is one of `types`. Throws when called with none. */
  resourceType(...types: (TResource | '*')[]): this {
    assertNonEmptyList('resourceType', types)
    this._items.push({ field: 'resource.type', operator: 'in', value: [...types] })
    return this
  }

  /**
   * Asserts on `subject.attributes.<path>`.
   *
   * @example
   * ```ts
   * w.attr('department', 'eq', 'engineering') // subject.attributes.department == 'engineering'
   * ```
   */
  attr<K extends DotPath.SubjectAttrs<TContext> & string>(
    path: K,
    op: AccessControl.Operator,
    value?:
      | DotPath.ConditionValue<TContext, DotPath.AttrValue<DotPath.SubjectAttrShape<TContext>, K>>
      | DotPath.FlexibleDollarPaths<TContext>,
  ): this {
    this._items.push({ field: `subject.attributes.${path}`, operator: op, value })
    return this
  }

  /**
   * Asserts on `resource.attributes.<path>`, typed by the resource selected with `RuleBuilder.of()`.
   *
   * @example
   * ```ts
   * w.resourceAttr('status', 'eq', 'published') // resource.attributes.status == 'published'
   * ```
   */
  resourceAttr<K extends DotPath.ResolvedResourceAttrPaths<TContext, TActiveResource> & string>(
    path: K,
    op: AccessControl.Operator,
    value?:
      | DotPath.ConditionValue<TContext, DotPath.AttrValue<DotPath.ResolvedResourceAttrs<TContext, TActiveResource>, K>>
      | DotPath.FlexibleDollarPaths<TContext>,
  ): this {
    this._items.push({ field: `resource.attributes.${path}`, operator: op, value })
    return this
  }

  /**
   * Asserts on `environment.<path>`, e.g. a time window.
   *
   * @example
   * ```ts
   * w.env('hour', 'gte', 9).env('hour', 'lte', 17) // environment.hour >= 9 AND environment.hour <= 17
   * ```
   */
  env<K extends DotPath.EnvAttrs<TContext> & string>(
    path: K,
    op: AccessControl.Operator,
    value?:
      | DotPath.ConditionValue<TContext, DotPath.AttrValue<DotPath.EnvAttrShape<TContext>, K>>
      | DotPath.FlexibleDollarPaths<TContext>,
  ): this {
    this._items.push({ field: `environment.${path}`, operator: op, value })
    return this
  }

  /**
   * Shared shape of `and`/`or`/`not`: build a fresh nested {@link When} via `fn`, then push whichever
   * group `close` emits from it. Only which terminal `build*` method closes the group differs between the three.
   * SECURITY: routed through `iamChosenWhen`, as `when()`/`whenAny()`/`grantWhen()` are - a callback that
   * returns a different builder than it was given must not silently empty the nested group.
   */
  private buildNested(
    fn: WhenGroupFn<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    close: (
      w: When<TAction, TResource, TRole, TScope, TContext, TActiveResource>,
    ) => AccessControl.ICondition | AccessControl.IConditionGroup,
  ): this {
    const nested = new When<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
    this._items.push(close(iamChosenWhen(nested, fn(nested))))
    return this
  }

  /**
   * Appends a nested AND group as a single item.
   *
   * @example
   * ```ts
   * w.and(a => a.attr('tier', 'eq', 'premium').env('region', 'eq', 'us'))
   * ```
   */
  and(fn: WhenGroupFn<TAction, TResource, TRole, TScope, TContext, TActiveResource>): this {
    return this.buildNested(fn, (w) => w.buildAll())
  }

  /**
   * Appends a nested OR group as a single item.
   *
   * @example
   * ```ts
   * w.or(o => o.isOwner().role('admin')) // owner OR admin
   * ```
   */
  or(fn: WhenGroupFn<TAction, TResource, TRole, TScope, TContext, TActiveResource>): this {
    return this.buildNested(fn, (w) => w.buildAny())
  }

  /**
   * Appends a nested NOT group: passes only if none of its conditions hold.
   *
   * @example
   * ```ts
   * w.not(n => n.attr('status', 'eq', 'banned')) // status is NOT 'banned'
   * ```
   */
  not(fn: WhenGroupFn<TAction, TResource, TRole, TScope, TContext, TActiveResource>): this {
    return this.buildNested(fn, (w) => w.buildNone())
  }

  /** Emits a copy of the conditions as `{ all }` (AND); used by `when()` and `grantWhen()`. */
  buildAll(): { readonly all: ReadonlyArray<AccessControl.ICondition | AccessControl.IConditionGroup> } {
    return { all: [...this._items] }
  }

  /** Emits a copy of the conditions as `{ any }` (OR), as `RuleBuilder.whenAny` does. */
  buildAny(): { readonly any: ReadonlyArray<AccessControl.ICondition | AccessControl.IConditionGroup> } {
    return { any: [...this._items] }
  }

  /** Emits a copy of the conditions as `{ none }` (NOT), as {@link When.not} does. */
  buildNone(): { readonly none: ReadonlyArray<AccessControl.ICondition | AccessControl.IConditionGroup> } {
    return { none: [...this._items] }
  }
}

/**
 * Refuses a zero-argument `roles()`, `scopes()` or `resourceType()`, which would build `in: []` and match nothing.
 * SECURITY: on a deny rule that removes the guard. A computed `w.in(field, [])` is left alone.
 */
function assertNonEmptyList(method: 'roles' | 'scopes' | 'resourceType', values: readonly string[]): void {
  if (values.length > 0) return
  throwIamError('IAM_BUILDER_WHEN_EMPTY_LIST', { method })
}

/**
 * Picks the builder a condition callback meant: the returned one when it differs from the one given.
 * SECURITY: ignoring a returned group leaves `{ all: [] }`, an unconditional grant. Conditions on both throw.
 */
export function iamChosenWhen<W extends { buildAll(): { readonly all: readonly unknown[] } }>(
  given: W,
  returned: W,
): W {
  if (!(returned instanceof When) || returned === given) return given
  if (given.buildAll().all.length > 0) {
    throwIamError('IAM_BUILDER_WHEN_GROUP_CONFLICT')
  }
  return returned
}

/**
 * Creates a standalone {@link When}, e.g. for a reusable condition group shared across rules.
 *
 * @example
 * ```ts
 * import { when } from '@gentleduck/iam'
 *
 * const ownerOrAdmin = when()
 *   .or(o => o.isOwner().role('admin'))
 *   .buildAll()
 * ```
 *
 * @template TAction        - Union of valid action strings
 * @template TResource       - Union of valid resource strings
 * @template TRole           - Union of valid role ID strings
 * @template TScope          - Union of valid scope strings
 * @template TContext        - Shape of the full evaluation context for typed dot-paths
 * @template TActiveResource - Resource narrowed by the parent `RuleBuilder.of()` (typed `resourceAttr`)
 */
export const when = <
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TContext extends object = DotPath.IDefaultContext,
  TActiveResource extends string = string,
>() => new When<TAction, TResource, TRole, TScope, TContext, TActiveResource>()
