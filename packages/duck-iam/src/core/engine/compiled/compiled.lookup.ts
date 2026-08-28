/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { evalConditionGroup } from '../../conditions'
import { evaluatePolicyFast } from '../../evaluate/evaluate'
import { combiners } from '../../evaluate/evaluate.libs'
import type { AccessControl, IamRequest } from '../../types'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

type Caches = { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> }
type OnPolicyError = (err: Error, policy: AccessControl.IPolicy) => void

/** Folds one DYNAMIC cell's per-policy votes into a single boolean (ABAC flatPolicies only - RBAC is a separate top-level vote, see `rbacVote`). */
function evaluateDynamicCell(
  groups: readonly DynamicPolicyGroup[],
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  combine: AccessControl.PolicyCombine,
  caches?: Caches,
  onPolicyError?: OnPolicyError,
): boolean {
  const perPolicy: boolean[] = []
  for (const group of groups) {
    try {
      const matched = group.rules
        .filter((rule) => evalConditionGroup(req, rule.conditions, 0, caches))
        .map((rule) => ({ rule, effect: rule.effect }))
      const decision = combiners[group.algorithm](matched, defaultEffect)
      perPolicy.push(decision.effect === 'allow')
    } catch (err) {
      // Rotten rule drops its policy as NotApplicable, same as evaluateFast's safeEval -
      // but still reported, same as evaluateFast's safeEval does via onPolicyError.
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), group.policy)
    }
  }
  if (perPolicy.length === 0) return defaultEffect === 'allow'
  return combine === 'allow-overrides' ? perPolicy.some(Boolean) : perPolicy.every(Boolean)
}

/**
 * The ABAC flat layer's vote at one cell: `null` only when the table has no ABAC flat
 * source at all. An unknown or untouched cell votes the constant `defaultEffect` - every
 * flatPolicies entry is applicable-but-absent there, which trivially reduces to that
 * constant under both `'and'` and `'allow-overrides'`. Does not know about RBAC.
 */
function abacFlatVote(
  table: CompiledTable,
  action: string,
  resource: string,
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  caches?: Caches,
  onPolicyError?: OnPolicyError,
): boolean | null {
  if (!table.hasFlatSource) return null

  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  if (a === undefined || r === undefined) return defaultEffect === 'allow'
  const idx = a * table.nResources + r
  if (table.touched[idx] === 0) return defaultEffect === 'allow'

  const k = table.kind[idx]
  if (k === CellKind.CONST_ALLOW) return true
  if (k === CellKind.CONST_DENY) return false

  // DYNAMIC
  const groups = table.dynamic[idx]
  if (!groups) return defaultEffect === 'allow'
  return evaluateDynamicCell(groups, req, defaultEffect, table.policyCombine, caches, onPolicyError)
}

/**
 * RBAC's single vote: the fast mask-bit check (`allow`), OR'd with the residual policy's
 * vote when the mask misses, falling back to `defaultEffect` when neither source has a
 * matching grant. `null` only when the table has no RBAC source at all (no role has any
 * permission). See compiled.types.ts's `rbacResidual` doc for why this must stay ONE vote.
 */
function rbacVote(
  table: CompiledTable,
  mask: number,
  action: string,
  resource: string,
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  caches?: Caches,
  onPolicyError?: OnPolicyError,
): boolean | null {
  if (!table.hasRbacSource) return null

  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  const maskHit = a !== undefined && r !== undefined && (mask & table.allow[a * table.nResources + r]!) !== 0
  if (maskHit) return true

  if (!table.rbacResidual) return defaultEffect === 'allow'
  try {
    return evaluatePolicyFast(table.rbacResidual, req, defaultEffect, caches)
  } catch (err) {
    onPolicyError?.(err instanceof Error ? err : new Error(String(err)), table.rbacResidual)
    return defaultEffect === 'allow'
  }
}

/**
 * Answers every request definitively - no `'fallthrough'`. Combines the ABAC flat vote,
 * the RBAC vote, and one vote per residual (targeted/wildcard) policy, mirroring
 * `evaluateFast`'s own top-level combine, error handling, and `failOpen` signal.
 */
export function lookup(
  table: CompiledTable,
  mask: number,
  action: string,
  resource: string,
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  onPolicyError?: OnPolicyError,
  signals?: { failOpen?: boolean },
  caches?: Caches,
): boolean {
  const applicable: boolean[] = []

  const abac = abacFlatVote(table, action, resource, req, defaultEffect, caches, onPolicyError)
  if (abac !== null) applicable.push(abac)

  const rbac = rbacVote(table, mask, action, resource, req, defaultEffect, caches, onPolicyError)
  if (rbac !== null) applicable.push(rbac)

  for (const policy of table.residualPolicies) {
    // Same fail-skip contract as evaluateFast's safeEval: one rotten residual
    // policy must not fail-closed the whole request.
    try {
      const vote = evaluatePolicyFast(policy, req, defaultEffect, caches)
      if (vote !== null) applicable.push(vote)
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), policy)
    }
  }

  if (applicable.length === 0) {
    const allowed = defaultEffect === 'allow'
    if (signals && allowed) signals.failOpen = true
    return allowed
  }
  return table.policyCombine === 'allow-overrides' ? applicable.some(Boolean) : applicable.every(Boolean)
}
