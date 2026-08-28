export enum CellKind {
  CONST_DENY = 0,
  CONST_ALLOW = 1,
  ROLE_MASK = 2,
  DYNAMIC = 3,
}

/** One policy's pre-filtered candidate rules for a single (action, resource) cell. */
export interface DynamicPolicyGroup {
  readonly policyId: string
  readonly algorithm: import('../../types').AccessControl.CombiningAlgorithm
  readonly rules: readonly import('../../types').AccessControl.IRule[]
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
  /** ROLE_MASK: grant mask. DYNAMIC: role-bypass fast path (may be 0). */
  readonly allow: Uint32Array
  readonly deny: Uint32Array
  /** Valid when kind === DYNAMIC. */
  readonly dynamic: (readonly DynamicPolicyGroup[] | undefined)[]
  /** True when any role contributes a simple (fast-bit) permission, or any flat-eligible ABAC policy exists. */
  readonly hasFlatSource: boolean
  /** True when this table's DYNAMIC cells must fold the RBAC mask-bit check in as one more mandatory 'and' vote instead of an allow-overrides-style bypass. */
  readonly foldRbacIntoAnd: boolean
  /** Policies excluded from the flat model: targeted, containing a non-literal action/resource rule, or (for the one synthesized RBAC entry) representing role permissions with `scope`/`conditions`. Evaluated per-request via `evaluatePolicyFast`. */
  readonly residualPolicies: readonly import('../../types').AccessControl.IPolicy[]
}
