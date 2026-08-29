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

export interface CompiledTable {
  readonly nResources: number
  readonly actionId: ReadonlyMap<string, number>
  readonly resourceId: ReadonlyMap<string, number>
  readonly roleId: ReadonlyMap<string, number>
  readonly policyCombine: import('../../types').AccessControl.PolicyCombine
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
