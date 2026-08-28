/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { evalConditionGroup } from '../../conditions'
import { evaluatePolicyFast } from '../../evaluate/evaluate'
import { combiners } from '../../evaluate/evaluate.libs'
import type { AccessControl, IamRequest } from '../../types'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

/**
 * Folds one DYNAMIC cell's per-policy votes into a single boolean. `rbacVote`, when passed,
 * is one more mandatory voter (the RBAC mask-bit check) ahead of every group's own vote.
 */
function evaluateDynamicCell(
  groups: readonly DynamicPolicyGroup[],
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  combine: AccessControl.PolicyCombine,
  rbacVote?: boolean,
): boolean {
  const perPolicy: boolean[] = rbacVote === undefined ? [] : [rbacVote]
  for (const group of groups) {
    try {
      const matched = group.rules
        .filter((rule) => evalConditionGroup(req, rule.conditions, 0))
        .map((rule) => ({ rule, effect: rule.effect }))
      const decision = combiners[group.algorithm](matched, defaultEffect)
      perPolicy.push(decision.effect === 'allow')
    } catch {
      // Rotten rule drops its policy as NotApplicable, same as evaluateFast's safeEval.
    }
  }
  if (perPolicy.length === 0) return defaultEffect === 'allow'
  return combine === 'allow-overrides' ? perPolicy.some(Boolean) : perPolicy.every(Boolean)
}

/**
 * The flat layer's vote at one cell: `null` only when the table has no flat source at all.
 * An unknown or untouched cell votes the constant `defaultEffect` - every flat source is
 * applicable-but-absent there, which trivially reduces to that constant under both `'and'`
 * and `'allow-overrides'`.
 */
function flatVote(
  table: CompiledTable,
  mask: number,
  action: string,
  resource: string,
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
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
  if (k === CellKind.ROLE_MASK) return (mask & table.allow[idx]!) !== 0

  // DYNAMIC
  const groups = table.dynamic[idx]
  if (!groups) return defaultEffect === 'allow'
  if (table.foldRbacIntoAnd) {
    return evaluateDynamicCell(groups, req, defaultEffect, table.policyCombine, (mask & table.allow[idx]!) !== 0)
  }
  if ((mask & table.allow[idx]!) !== 0) return true // role-bypass fast path
  return evaluateDynamicCell(groups, req, defaultEffect, table.policyCombine)
}

/**
 * Answers every request definitively - no `'fallthrough'`. Combines the flat layer's vote
 * with one vote per residual policy (`evaluatePolicyFast`), mirroring `evaluateFast`'s own
 * top-level combine.
 */
export function lookup(
  table: CompiledTable,
  mask: number,
  action: string,
  resource: string,
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
): boolean {
  const flat = flatVote(table, mask, action, resource, req, defaultEffect)

  const applicable: boolean[] = []
  for (const policy of table.residualPolicies) {
    const vote = evaluatePolicyFast(policy, req, defaultEffect)
    if (vote !== null) applicable.push(vote)
  }
  if (flat !== null) applicable.push(flat)

  if (applicable.length === 0) return defaultEffect === 'allow'
  return table.policyCombine === 'allow-overrides' ? applicable.some(Boolean) : applicable.every(Boolean)
}
