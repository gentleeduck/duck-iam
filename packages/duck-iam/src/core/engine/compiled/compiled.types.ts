/**
 * How one (action, resource) cell is answered: `CONST_*` is settled at compile time and needs a bit test;
 * `DYNAMIC` (conditions or targeting) evaluates the cell's groups per request.
 */
export enum CellKind {
  CONST_DENY = 0,
  CONST_ALLOW = 1,
  DYNAMIC = 2,
}

/**
 * A literal-action/resource role permission with a scope and/or conditions, pre-filtered to one cell.
 * WARN: folded into the single RBAC vote by `rbacVote()`, never a separate voter; see `CompiledTable.rbacResidual`.
 */
export interface RbacRuleGroup {
  /** One bit per role holding this permission, inheritance-expanded like the `allow` mask. */
  readonly roleMask: number
  /** Literal scope required, if any (`perm.scope ?? role.scope`, excluding `undefined`/`'*'`). */
  readonly scope?: string
  /** `perm.conditions`, if any. */
  readonly conditions?: import('../../types').AccessControl.IConditionGroup
  /** Synthetic policy shared by every rbacDynamic group so a bad condition reaches `onPolicyError`. Never evaluated. */
  readonly policy: import('../../types').AccessControl.IPolicy
}

/** One policy's pre-filtered candidate rules for a single (action, resource) cell. */
export interface DynamicPolicyGroup {
  readonly policyId: string
  readonly algorithm: import('../../types').AccessControl.CombiningAlgorithm
  readonly rules: readonly import('../../types').AccessControl.IRule[]
  /** The policy itself, so a rotten rule can be reported via `onPolicyError`. */
  readonly policy: import('../../types').AccessControl.IPolicy
  /** Subject must hold one of these roles for this group to vote. `undefined` = applies to everyone. */
  readonly targetRoles?: readonly string[]
}

/**
 * The model baked into flat arrays indexed by `actionId * nResources + resourceId`, so most checks are a bit test.
 * NOTE: never mutated; replaced wholesale on invalidation so a request already reading it sees one consistent model.
 */
export interface CompiledTable {
  readonly nResources: number
  readonly actionId: ReadonlyMap<string, number>
  readonly resourceId: ReadonlyMap<string, number>
  readonly roleId: ReadonlyMap<string, number>
  readonly policyCombine: import('../../types').AccessControl.PolicyCombine
  /**
   * `IConfig.scopeMode`, baked in because {@link RbacRuleGroup} scopes are matched at lookup;
   * `'hierarchical'` also matches descendant scopes.
   */
  readonly scopeMode: 'flat' | 'hierarchical'
  /** idx = actionId(a) * nResources + resourceId(r) indexes every array below. */
  readonly kind: Uint8Array
  /** 0 means the flat layer has no vote at this cell (defaultEffect applies). */
  readonly touched: Uint8Array
  /** RBAC grant mask, one bit per role (see `roleId`), filled regardless of `kind`. Read only by `rbacVote()`. */
  readonly allow: Uint32Array
  /** Valid when kind === DYNAMIC. */
  readonly dynamic: (readonly DynamicPolicyGroup[] | undefined)[]
  /**
   * Scoped and/or conditioned literal role permissions per cell. `rbacVote()` checks them after the mask misses
   * and before `rbacResidual`, as part of the one RBAC vote.
   */
  readonly rbacDynamic: (readonly RbacRuleGroup[] | undefined)[]
  /** True when any flat-eligible ABAC policy exists (RBAC is tracked separately - see `hasRbacSource`). */
  readonly hasFlatSource: boolean
  /** True when any role grants a permission; only then does RBAC vote in `lookup()`. */
  readonly hasRbacSource: boolean
  /**
   * The `__rbac__`-style policy for wildcarded action/resource role permissions, or `null` if there are none.
   * WARN: `allow`, `rbacDynamic` and this are OR'd into ONE RBAC vote; as three voters an 'and' table would veto.
   */
  readonly rbacResidual: import('../../types').AccessControl.IPolicy | null
  /**
   * Policies outside the flat model (targeted, or with a non-literal action/resource), run per request via
   * `evaluatePolicyFast`. Excludes RBAC; see `rbacResidual`.
   */
  readonly residualPolicies: readonly import('../../types').AccessControl.IPolicy[]
}
