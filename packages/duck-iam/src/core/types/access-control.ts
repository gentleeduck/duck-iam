import type { IamClient } from './client'
import type { IamPrimitives } from './primitives'

/**
 * The authorization model: policies, rules, roles and the algorithms that combine their votes. Type-only.
 * Generic over the caller's action/resource/role/scope unions, so a typo in a rule is a compile error.
 */
export namespace AccessControl {
  /**
   * The outcome a rule produces when it matches: grant or block access.
   *
   * @example
   * ```ts
   * const allow: AccessControl.Effect = 'allow'
   * const deny:  AccessControl.Effect = 'deny'
   * ```
   */
  export type Effect = 'allow' | 'deny'

  /**
   * Comparison operators supported by the condition engine.
   *
   * | Operator | Meaning |
   * |---|---|
   * | `eq` / `neq` | Equals / not equals |
   * | `gt` / `gte` / `lt` / `lte` | Numeric comparisons |
   * | `in` / `nin` | Value is / is not in the given array |
   * | `contains` / `not_contains` | Array contains / does not contain the value |
   * | `starts_with` / `ends_with` | String prefix / suffix |
   * | `matches` | String matches a regex pattern |
   * | `exists` / `not_exists` | Field is / is not defined |
   * | `subset_of` / `superset_of` | Array subset / superset check |
   * | `before` / `after` | Temporal compare; operands coerced to epoch ms (number or ISO-8601 string) |
   */
  export type Operator =
    | 'eq'
    | 'neq'
    | 'gt'
    | 'gte'
    | 'lt'
    | 'lte'
    | 'in'
    | 'nin'
    | 'contains'
    | 'not_contains'
    | 'starts_with'
    | 'ends_with'
    | 'matches'
    | 'exists'
    | 'not_exists'
    | 'subset_of'
    | 'superset_of'
    | 'before'
    | 'after'

  /**
   * Leaf condition: compares a dot-path field against a value via an
   * {@link Operator}. Building block of {@link IConditionGroup} trees.
   */
  export interface ICondition {
    /** Dot-path to the attribute being tested (e.g. `'subject.attributes.status'`). */
    readonly field: string
    /** Comparison operator to apply. */
    readonly operator: Operator
    /** Right-hand side value. Omit for unary operators like `exists`. */
    readonly value?: IamPrimitives.AttributeValue
  }

  /** Every child must hold. */
  export interface IConditionAll {
    readonly all: ReadonlyArray<ICondition | IConditionGroup>
  }

  /** At least one child must hold. */
  export interface IConditionAny {
    readonly any: ReadonlyArray<ICondition | IConditionGroup>
  }

  /** No child may hold. */
  export interface IConditionNone {
    readonly none: ReadonlyArray<ICondition | IConditionGroup>
  }

  /**
   * Recursive condition tree with exactly one key: `all` (AND), `any` (OR), or `none` (NOT / NOR).
   * NOTE: keep the arms named; with anonymous arms, schema generators such as typia inline the tree until they crash.
   */
  export type IConditionGroup = IConditionAll | IConditionAny | IConditionNone

  /**
   * Atomic unit of an ABAC policy. Declares an {@link Effect}, the actions /
   * resources it covers, an optional priority, and a condition tree that must
   * hold for the rule to fire.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   */
  export interface IRule<TAction extends string = string, TResource extends string = string> {
    readonly id: string
    readonly effect: Effect
    /** Human-readable description for audit logs and explain output. */
    readonly description?: string
    /** Higher values evaluated first under `highest-priority` and `first-match`. */
    readonly priority: number
    /** Actions this rule applies to. `'*'` matches all actions. */
    readonly actions: readonly (TAction | '*')[]
    /** Resources this rule applies to. `'*'` matches all resources. */
    readonly resources: readonly (TResource | '*')[]
    readonly conditions: IConditionGroup
    /** Arbitrary metadata for admin dashboards, audit logs, or app bookkeeping. */
    readonly metadata?: Readonly<IamPrimitives.Attributes>
  }

  /**
   * Intra-policy rule conflict resolution.
   *
   * | Algorithm | Behavior |
   * |---|---|
   * | `deny-overrides` | Any deny wins. Default. |
   * | `allow-overrides` | Any allow wins. Best for RBAC / permissive rules. |
   * | `first-match` | Highest-priority match wins; ties resolved by source order. |
   * | `highest-priority` | Identical to `first-match`. |
   *
   * WARN: source order is the adapter's row order; give the rule meant to win a higher priority instead.
   */
  export type CombiningAlgorithm = 'deny-overrides' | 'allow-overrides' | 'first-match' | 'highest-priority'

  /**
   * Cross-policy combine strategy.
   *
   * | Mode | Behavior |
   * |---|---|
   * | `and` | Every policy must allow. Any deny is final. Default. |
   * | `allow-overrides` | Any policy that allows wins. |
   * | `first-applicable` | First policy that is not NotApplicable wins, including one that votes its default. |
   */
  export type PolicyCombine = 'and' | 'allow-overrides' | 'first-applicable'

  /**
   * An ABAC policy: named collection of {@link IRule} objects plus a
   * {@link CombiningAlgorithm}. Cross-policy decisions are merged by the
   * engine according to its `policyCombine` setting (default `'and'`).
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TRole     - Union of valid role IDs targeted by `targets.roles`.
   */
  export interface IPolicy<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
  > {
    readonly id: string
    readonly name: string
    readonly description?: string
    /** Version for tracking policy changes over time. */
    readonly version?: number
    readonly algorithm: CombiningAlgorithm
    readonly rules: readonly IRule<TAction, TResource>[]
    /**
     * Optional target constraints. The policy is skipped (NotApplicable) when
     * any specified dimension does not match the request.
     */
    readonly targets?: {
      readonly actions?: readonly (TAction | '*')[]
      readonly resources?: readonly (TResource | '*')[]
      readonly roles?: readonly TRole[]
    }
  }

  /**
   * One action/resource grant within an {@link IRole}; `rolesToPolicy()` turns each into an ABAC allow rule.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   */
  export interface IPermission<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    /** Action this permission grants, or `'*'` for all. */
    readonly action: TAction | '*'
    /** Resource this permission applies to, or `'*'` for all. */
    readonly resource: TResource | '*'
    /** Optional scope restriction. */
    readonly scope?: TScope | '*'
    /** Optional conditions (used by `grantWhen`). */
    readonly conditions?: IConditionGroup
  }

  /**
   * An RBAC role: named {@link IPermission} entries with optional inheritance, evaluated as ABAC rules.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TId       - Literal string type of the role ID.
   * @template TScope    - Union of valid scope strings.
   */
  export interface IRole<
    TAction extends string = string,
    TResource extends string = string,
    TId extends string = string,
    TScope extends string = string,
  > {
    readonly id: TId
    readonly name: string
    readonly description?: string
    readonly permissions: readonly IPermission<TAction, TResource, TScope>[]
    /** Parent role IDs to inherit permissions from (resolved recursively). */
    readonly inherits?: readonly string[]
    /** Default scope applied to all permissions in this role. */
    readonly scope?: TScope
    readonly metadata?: Readonly<IamPrimitives.Attributes>
  }

  /** Result of an authorization evaluation: the verdict plus which rule and policy produced it. */
  export interface IDecision {
    readonly allowed: boolean
    readonly effect: Effect
    readonly rule?: IRule
    /** ID of the policy that produced this decision (if any). */
    readonly policy?: string
    readonly reason: string
    /** Time in milliseconds the evaluation took. */
    readonly duration: number
    /** Unix timestamp (ms) when the decision was made. */
    readonly timestamp: number
    /** `false` when the policy's targets missed (NotApplicable); omitted or `true` when applicable. */
    readonly applicable?: boolean
    /**
     * Set when the deny came from the engine failing, not a policy saying no, so callers can tell a 503 from a 403.
     * `'input'`: malformed request; `'resolution'`: subject not resolved (adapter outage); `'evaluation'`: threw.
     * INFO: production mode returns a bare boolean and cannot carry this; use the engine's `onError` hook there.
     */
    readonly failure?: 'input' | 'resolution' | 'evaluation'
  }

  /**
   * Engine execution mode. `'production'` (default) returns plain booleans, with no timing or reason strings.
   * `'development'` returns rich {@link IDecision} objects and enables the explain/debug API.
   */
  export type Mode = 'development' | 'production'

  /**
   * Conditional return type based on engine mode. Production -> `boolean`,
   * development -> {@link IDecision}.
   *
   * @template M - The engine {@link Mode}.
   */
  export type ModeResult<M extends Mode> = M extends 'production' ? boolean : IDecision

  /**
   * Permission map by mode: production -> `Record<string, boolean>`, development -> {@link IamClient.PermissionMap}.
   *
   * @template M         - The engine {@link Mode}.
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   */
  export type ModePermissionMap<
    M extends Mode,
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > = M extends 'production' ? Record<string, boolean> : IamClient.PermissionMap<TAction, TResource, TScope>

  /** One operator implementation, evaluating a condition's `(field, value)` pair. */
  export type OpFn = (field: IamPrimitives.AttributeValue, value: IamPrimitives.AttributeValue) => boolean

  /**
   * `onPolicyError` shape for the evaluator: the second argument is the throwing {@link IPolicy} itself.
   * WARN: an inline arrow compiles against all three shapes below, so a logger written for one misprints on another.
   * SECURITY: the throwing policy is Indeterminate, never NotApplicable, so a malformed deny rule is not skipped.
   *
   * | Where | Second argument |
   * |---|---|
   * | `iamEvaluate` / `iamEvaluateFast` | this type - the policy object |
   * | `IamEngineTypes.IHooks.onPolicyError` | the policy **id**, a string |
   * | adapter configs | `IamAdapter.RowErrorHandler`'s `{ adapter, rowId }` |
   */
  export type PolicyErrorHandler<TAction extends string = string, TResource extends string = string> = (
    err: Error,
    policy: IPolicy<TAction, TResource>,
  ) => void
}
