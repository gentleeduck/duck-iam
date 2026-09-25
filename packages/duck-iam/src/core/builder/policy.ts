import { throwIamValidationFailed } from '../errors'
import type { AccessControl, DotPath } from '../types'
import { validatePolicy } from '../validate'
import { RuleBuilder } from './rule'

/**
 * Chainable builder for an ABAC {@link AccessControl.IPolicy}: time windows, geo-fencing, maintenance guards.
 * `.algorithm()` resolves conflicts between its rules; {@link AccessControl.PolicyCombine} merges policies.
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role strings.
 * @template TScope    - Union of valid scope strings.
 * @template TContext  - Shape of the full evaluation context for typed dot-paths.
 *
 * @example
 * ```typescript
 * import { definePolicy } from '@gentleduck/iam'
 *
 * const weekendDeny = definePolicy('deny-weekends')
 *   .name('Deny on Weekends')
 *   .desc('Block all write operations on weekends')
 *   .version(1)
 *   .algorithm('deny-overrides')
 *   .rule('r-deny-weekends', r => r
 *     .deny()
 *     .on('create', 'update', 'delete')
 *     .of('*')
 *     .when(w => w.env('dayOfWeek', 'in', [0, 6]))
 *   )
 *   .build()
 * ```
 */
export class PolicyBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TContext extends object = DotPath.IDefaultContext,
> {
  private _id: string
  private _name: string
  private _description?: string
  private _algorithm: AccessControl.CombiningAlgorithm = 'deny-overrides'
  private _rules: AccessControl.IRule<TAction, TResource>[] = []
  private _targets?: AccessControl.IPolicy<TAction, TResource, TRole>['targets']
  private _version?: number

  constructor(id: string) {
    this._id = id
    this._name = id
  }

  /** Sets the display name; defaults to the policy ID. */
  name(n: string): this {
    this._name = n
    return this
  }

  /** Sets the description. */
  desc(d: string): this {
    this._description = d
    return this
  }

  /** Sets a version number for tracking changes. */
  version(v: number): this {
    this._version = v
    return this
  }

  /**
   * Sets how conflicts between this policy's rules resolve; defaults to `'deny-overrides'`.
   * See {@link AccessControl.CombiningAlgorithm} for what each algorithm does.
   */
  algorithm(a: AccessControl.CombiningAlgorithm): this {
    this._algorithm = a
    return this
  }

  /**
   * Limits the policy to requests matching all given targets; any other request skips its rules entirely.
   *
   * @example
   * ```typescript
   * definePolicy('write-restrictions')
   *   .target({
   *     actions: ['create', 'update', 'delete'],
   *     resources: ['post', 'comment'],
   *   })
   * ```
   */
  target(t: NonNullable<AccessControl.IPolicy<TAction, TResource, TRole>['targets']>): this {
    this._targets = t
    return this
  }

  /**
   * Adds a rule built by an inline {@link RuleBuilder} callback.
   *
   * @example
   * ```typescript
   * definePolicy('ip-guard')
   *   .rule('block-bad-ips', r => r
   *     .deny()
   *     .on('*')
   *     .of('*')
   *     .when(w => w.env('ip', 'in', ['10.0.0.99', '10.0.0.100']))
   *   )
   * ```
   */
  rule(
    id: string,
    fn: (
      r: RuleBuilder<TAction, TResource, TScope, TRole, TContext>,
    ) => RuleBuilder<TAction, TResource, TScope, TRole, TContext, any>,
  ): this {
    // Honour a different returned builder, as the condition callbacks do. An unconfigured one throws in `build()`.
    const builder = new RuleBuilder<TAction, TResource, TScope, TRole, TContext>(id)
    const returned = fn(builder)
    this._rules.push((returned instanceof RuleBuilder ? returned : builder).build())
    return this
  }

  /**
   * Adds a pre-built {@link AccessControl.IRule}, e.g. one from `defineRule`.
   *
   * @example
   * ```typescript
   * import { defineRule } from '@gentleduck/iam'
   *
   * const denyDrafts = defineRule('deny-drafts')
   *   .deny()
   *   .on('read')
   *   .of('post')
   *   .when(w => w.resourceAttr('status', 'eq', 'draft'))
   *   .build()
   *
   * definePolicy('post-access').addRule(denyDrafts)
   * ```
   */
  addRule(rule: AccessControl.IRule<TAction, TResource>): this {
    this._rules.push(rule)
    return this
  }

  /**
   * Returns the plain {@link AccessControl.IPolicy}, ready for an adapter or the engine.
   *
   * @throws If the policy fails validation
   */
  build(): AccessControl.IPolicy<TAction, TResource, TRole> {
    // Omit unset optional keys instead of writing `undefined`: memory keeps such a key and JSON-backed stores
    // drop it, so the same policy would read back unequal.
    const policy: AccessControl.IPolicy<TAction, TResource, TRole> = {
      id: this._id,
      name: this._name,
      ...(this._description === undefined ? {} : { description: this._description }),
      ...(this._version === undefined ? {} : { version: this._version }),
      algorithm: this._algorithm,
      rules: [...this._rules],
      ...(this._targets === undefined ? {} : { targets: this._targets }),
    }
    // Validate here too: saving straight to an adapter skips `engine.admin.savePolicy`'s validator.
    const result = validatePolicy(policy)
    if (!result.valid) throwIamValidationFailed('policy', result.issues)
    return policy
  }
}

/**
 * Creates a {@link PolicyBuilder}; `id` doubles as the default name.
 * With `createIam`, use `access.definePolicy()` for typed actions, resources and roles.
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role strings.
 * @template TScope    - Union of valid scope strings.
 * @template TContext  - Shape of the full evaluation context for typed dot-paths.
 *
 * @example
 * ```typescript
 * import { definePolicy } from '@gentleduck/iam'
 *
 * const maintenanceMode = definePolicy('maintenance-mode')
 *   .name('Maintenance Mode')
 *   .desc('Deny all writes when the maintenance flag is active')
 *   .algorithm('deny-overrides')
 *   .rule('deny-writes', r => r
 *     .deny()
 *     .on('create', 'update', 'delete')
 *     .of('*')
 *     .when(w => w.env('maintenanceMode', 'eq', true))
 *   )
 *   .build()
 * ```
 */
export const definePolicy = <
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TContext extends object = DotPath.IDefaultContext,
>(
  id: string,
) => new PolicyBuilder<TAction, TResource, TRole, TScope, TContext>(id)
