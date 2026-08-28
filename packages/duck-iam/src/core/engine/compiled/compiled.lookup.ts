/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { evalConditionGroup } from '../../conditions'
import { evaluatePolicyFast } from '../../evaluate/evaluate'
import { combiners } from '../../evaluate/evaluate.libs'
import type { AccessControl, IamRequest } from '../../types'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

type Caches = { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> }
type OnPolicyError = (err: Error, policy: AccessControl.IPolicy) => void

/**
 * Folds one DYNAMIC cell's per-policy votes into a single boolean (ABAC flatPolicies only -
 * RBAC is a separate top-level vote, see `rbacVote`). Returns `null` only when every group at
 * this cell threw - same fail-skip contract as `evaluatePolicyFast`'s residual-policy loop: a
 * cell with zero surviving votes must abstain, not fail-closed the whole request.
 */
function evaluateDynamicCell(
  groups: readonly DynamicPolicyGroup[],
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  combine: AccessControl.PolicyCombine,
  caches?: Caches,
  onPolicyError?: OnPolicyError,
): boolean | null {
  const perPolicy: boolean[] = []
  const subjectRoles = Array.isArray(req.subject.roles) ? req.subject.roles : []
  for (const group of groups) {
    // Role-targeted group: subject without the role doesn't get a vote from it at all
    // (same as policyApplies()'s target check) - not a deny, just not a voter.
    if (group.targetRoles && !group.targetRoles.some((r) => subjectRoles.includes(r))) continue
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
  if (perPolicy.length === 0) return null
  return combine === 'allow-overrides' ? perPolicy.some(Boolean) : perPolicy.every(Boolean)
}

/**
 * The ABAC flat layer's vote at one cell: `null` when the table has no ABAC flat source at
 * all, when no flat policy has any rule shaped for this action/resource (unknown dimension
 * or an untouched cell - no policy has anything to say here, same as `evaluatePolicy`'s
 * rule-shape NotApplicable check), or when a DYNAMIC cell's every policy group threw
 * (abstain, don't fail-closed). Does not know about RBAC.
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
  if (a === undefined || r === undefined) return null
  const idx = a * table.nResources + r
  if (table.touched[idx] === 0) return null

  const k = table.kind[idx]
  if (k === CellKind.CONST_ALLOW) return true
  if (k === CellKind.CONST_DENY) return false

  // DYNAMIC
  const groups = table.dynamic[idx]
  if (!groups) return null
  return evaluateDynamicCell(groups, req, defaultEffect, table.policyCombine, caches, onPolicyError)
}

/**
 * RBAC's single vote: the fast mask-bit check (`allow`), OR'd with the residual policy's
 * vote when the mask misses, falling back to `defaultEffect` only when some role
 * elsewhere in the system DOES grant this exact action+resource (so the miss is a real
 * "not this subject's roles", not "nobody's talking about this"). `null` when the table
 * has no RBAC source at all, when neither half has anything shaped for this action/
 * resource, or when the residual policy throws (abstain, same fail-skip contract as
 * `evaluatePolicyFast`'s residual-policy loop below - a rotten `__rbac__` policy must not
 * fail-closed the whole request). See compiled.types.ts's `rbacResidual` doc for why this
 * must stay ONE vote.
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

  // `actionId`/`resourceId` are shared with the ABAC flat layer - a dimension can exist
  // solely because some ABAC policy uses it, with no role ever granting it. So "does the
  // grant mask cell exist" is not "is this a known dimension"; it's "is this cell's raw
  // grant value (any role, not just this subject's) nonzero" - that's RBAC-specific.
  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  const cellAllow = a !== undefined && r !== undefined ? table.allow[a * table.nResources + r]! : 0
  if ((mask & cellAllow) !== 0) return true

  if (table.rbacResidual) {
    try {
      const vote = evaluatePolicyFast(table.rbacResidual, req, defaultEffect, caches)
      if (vote !== null) return vote
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), table.rbacResidual)
      return null
    }
  }

  // Neither half has a rule shaped for this action/resource. A nonzero grant at this
  // cell (from any role, not just this subject's) means some role's simple permission
  // does grant this exact pair - just not one this subject holds - so that's still a
  // real vote, not silence.
  return cellAllow !== 0 ? defaultEffect === 'allow' : null
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
