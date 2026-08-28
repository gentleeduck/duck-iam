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
  /** idx = actionId(a) * nResources + resourceId(r) indexes every array below. */
  readonly kind: Uint8Array
  /** 0 means fall through to evaluateFast. */
  readonly touched: Uint8Array
  /** ROLE_MASK: grant mask. DYNAMIC: role-bypass fast path (may be 0). */
  readonly allow: Uint32Array
  readonly deny: Uint32Array
  /** Valid when kind === DYNAMIC. */
  readonly dynamic: (readonly DynamicPolicyGroup[] | undefined)[]
}
