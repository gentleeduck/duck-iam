/**
 * How a single (action, resource) cell of the compiled table can be answered.
 *
 * `CONST_DENY` and `CONST_ALLOW` are settled at compile time and need only a
 * bit test at lookup. `DYNAMIC` means conditions or policy targeting make the
 * answer depend on the request, so the cell's groups must be evaluated per
 * call - the case the table exists to keep rare.
 */
export enum CellKind {
  CONST_DENY = 0,
  CONST_ALLOW = 1,
  DYNAMIC = 2,
}

/**
 * One non-simple-but-literal role permission (scope and/or conditions - never wildcarded
 * action/resource, that stays in `rbacResidual`), pre-filtered to a single (action, resource)
 * cell. Folded into the single RBAC vote by `rbacVote()` - never a separate voter, same
 * invariant as `rbacResidual` (see its own doc below).
 */
export interface RbacRuleGroup {
  /** Bit per role that holds this permission - inheritance-expanded, same math as the `allow` mask bake (`holders`). */
  readonly roleMask: number
  /** Literal scope required, if any (`perm.scope ?? role.scope`, excluding `undefined`/`'*'`). */
  readonly scope?: string
  /** `perm.conditions`, if any. */
  readonly conditions?: import('../../types').AccessControl.IConditionGroup
  /** Synthetic single-source policy shared by every rbacDynamic group, so a rotten condition can be reported via `onPolicyError` - mirrors `DynamicPolicyGroup.policy`. Never evaluated directly. */
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
 * The whole authorization model baked into flat arrays, indexed by
 * `actionId * nResources + resourceId`, so the common case is a bit test rather
 * than a walk over policies. Built once per model generation and replaced
 * wholesale on invalidation - never mutated, because a request already reading
 * it must see one consistent model.
 *
 * A cell falls into one of three classes (`kind`): a constant allow or deny the
 * lookup can answer from `allow`/`touched` alone, or DYNAMIC, where conditions
 * or targeting force per-request evaluation of `dynamic`. RBAC is deliberately
 * spread across three fields - the `allow` bitmask, `rbacDynamic`, and
 * `rbacResidual` - which together form ONE vote; see `rbacResidual` for why
 * treating them as three would break an 'and'-combined table.
 */
export interface CompiledTable {
  readonly nResources: number
  readonly actionId: ReadonlyMap<string, number>
  readonly resourceId: ReadonlyMap<string, number>
  readonly roleId: ReadonlyMap<string, number>
  readonly policyCombine: import('../../types').AccessControl.PolicyCombine
  /**
   * `IConfig.scopeMode`. Baked in at compile time because a role permission's
   * declared scope is stored literally on {@link RbacRuleGroup} and matched at
   * lookup time; under `'hierarchical'` that match covers descendant scopes.
   */
  readonly scopeMode: 'flat' | 'hierarchical'
  /** idx = actionId(a) * nResources + resourceId(r) indexes every array below. */
  readonly kind: Uint8Array
  /** 0 means the flat layer has no vote at this cell (defaultEffect applies). */
  readonly touched: Uint8Array
  /** The RBAC grant mask - one bit per role (see `roleId`), populated regardless of `kind`. Consulted only by `rbacVote()`, never by the ABAC-only cell classification. */
  readonly allow: Uint32Array
  /** Valid when kind === DYNAMIC. */
  readonly dynamic: (readonly DynamicPolicyGroup[] | undefined)[]
  /**
   * Scoped and/or conditioned role permissions (literal action+resource), grouped per cell -
   * same idx scheme as `allow`/`kind`/`dynamic`. Checked by `rbacVote()` after the plain
   * bitmask misses, before falling to `rbacResidual`. Part of RBAC's single vote, not a
   * separate voter (see `rbacResidual`'s doc).
   */
  readonly rbacDynamic: (readonly RbacRuleGroup[] | undefined)[]
  /** True when any flat-eligible ABAC policy exists (RBAC is tracked separately - see `hasRbacSource`). */
  readonly hasFlatSource: boolean
  /** True when any role contributes a permission at all (simple or residual) - RBAC participates as its own vote in `lookup()` iff this is true. */
  readonly hasRbacSource: boolean
  /**
   * The single `__rbac__`-equivalent policy for role permissions that can't take the
   * fast bit path at all - only wildcarded action/resource permissions now (scope and/or
   * conditions with a literal action+resource compile into `rbacDynamic` instead). `null`
   * when no role permission is wildcarded. This is ONE of three sources of the same logical
   * RBAC vote (`allow` mask bits, `rbacDynamic`, and this) - all three must be OR'd into a
   * single RBAC vote (`rbacVote()` in compiled.lookup.ts), never treated as independent
   * voters, or an 'and'-combine table would double-count RBAC and can spuriously veto every
   * request the other sources have no rule for.
   */
  readonly rbacResidual: import('../../types').AccessControl.IPolicy | null
  /** Policies excluded from the flat model: targeted, or containing a non-literal action/resource rule. Evaluated per-request via `evaluatePolicyFast`. Does NOT include RBAC - see `rbacResidual`. */
  readonly residualPolicies: readonly import('../../types').AccessControl.IPolicy[]
}
