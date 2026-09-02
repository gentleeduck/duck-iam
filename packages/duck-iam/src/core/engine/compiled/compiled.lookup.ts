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
      // An error is Indeterminate, not NotApplicable: a group carrying a deny rule
      // votes deny rather than dropping out, so padding a `matches` field cannot
      // silently retire it. Allow-only groups stay skippable. Reported either way.
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), group.policy)
      if (group.rules.some((rule) => rule.effect === 'deny')) perPolicy.push(false)
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
 * RBAC's single vote, OR'd across three sources - the fast mask-bit check (`allow`), the
 * per-cell scope/condition groups (`rbacDynamic`), and the wildcarded-permission residual
 * policy (`rbacResidual`) - falling back to `defaultEffect` only when some role elsewhere
 * in the system DOES grant this exact action+resource (so the miss is a real "not this
 * subject's roles", not "nobody's talking about this"). `null` when the table has no RBAC
 * source at all, when nothing is shaped for this action/resource, or when a source throws
 * (abstain, same fail-skip contract as `evaluatePolicyFast`'s residual-policy loop below -
 * a rotten permission must not fail-closed the whole request). See compiled.types.ts's
 * `rbacResidual` doc for why all three must stay ONE vote.
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
  const idx = a !== undefined && r !== undefined ? a * table.nResources + r : undefined
  const cellAllow = idx !== undefined ? table.allow[idx]! : 0
  if ((mask & cellAllow) !== 0) return true

  // Scoped/conditioned grants: one throw anywhere in this cell's groups poisons the whole
  // scan (same all-or-nothing granularity as `rbacResidual`'s catch below, not ABAC's
  // per-policy-group fail-skip) - abstain rather than risk a partial, order-dependent vote.
  const groups = idx !== undefined ? table.rbacDynamic[idx] : undefined
  if (groups) {
    try {
      for (const g of groups) {
        if ((mask & g.roleMask) === 0) continue
        if (g.scope !== undefined && g.scope !== req.scope) continue
        if (g.conditions && !evalConditionGroup(req, g.conditions, 0, caches)) continue
        return true // role permissions are allow-only - first match wins
      }
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), groups[0]!.policy)
      return null
    }
  }

  if (table.rbacResidual) {
    try {
      const vote = evaluatePolicyFast(table.rbacResidual, req, defaultEffect, caches)
      if (vote !== null) return vote
    } catch (err) {
      onPolicyError?.(err instanceof Error ? err : new Error(String(err)), table.rbacResidual)
      return null
    }
  }

  // No source has a rule shaped for this action/resource. A nonzero grant at this cell
  // (from any role, not just this subject's, via the plain mask or a scoped/conditioned
  // group) means some role's permission does grant this exact pair - just not one this
  // subject holds (or its scope/condition doesn't match) - so that's still a real vote,
  // not silence.
  const hasAnyGrant = cellAllow !== 0 || (groups !== undefined && groups.length > 0)
  return hasAnyGrant ? defaultEffect === 'allow' : null
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
