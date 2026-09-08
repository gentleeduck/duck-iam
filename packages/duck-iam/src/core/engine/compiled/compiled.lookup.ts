/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { evalConditionGroup } from '../../conditions/conditions'
import { evaluatePolicyFast, type IVoteSource } from '../../evaluate/evaluate'
import { combiners, policyHasDenyRule, safeErrorReport } from '../../evaluate/evaluate.libs'
import { IAM_RBAC_CONDITION_DEPTH } from '../../rbac/rbac'
import type { AccessControl, IamRequest } from '../../types'
import { scopeCovers } from '../engine.libs'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

type Caches = { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> }

/**
 * Folds one DYNAMIC cell's per-policy votes into a single boolean (ABAC flatPolicies only -
 * RBAC is a separate top-level vote, see `rbacVote`). Returns `null` only when every group at
 * this cell threw. A throw is Indeterminate: the group votes deny if its policy carries any
 * deny rule, otherwise it casts the `defaultEffect` vote it would have cast had it evaluated.
 * It never abstains - abstaining is what let a forced throw delete the vote.
 */
function evaluateDynamicCell(
  groups: readonly DynamicPolicyGroup[],
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  combine: AccessControl.PolicyCombine,
  caches?: Caches,
  onPolicyError?: AccessControl.PolicyErrorHandler,
  voteSource?: IVoteSource,
): boolean | null {
  if (voteSource) voteSource.fromDefault = false
  const perPolicy: boolean[] = []
  // Parallel to `perPolicy`: whether that group's allow came from `defaultEffect`
  // rather than from a rule that fired.
  const fromDefault: boolean[] = []
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
      fromDefault.push(decision.rule === undefined)
    } catch (err) {
      // An error is Indeterminate, not NotApplicable. The deny check is asked of
      // the whole *policy*, not of `group.rules` - a group holds only the rules
      // shaped for this action/resource cell, so a policy whose deny rule targets
      // a different cell reads as allow-only here and the vote is dropped. The
      // interpreter asks `policyHasDenyRule(policy)`; asking anything narrower is
      // what let production allow what development denied. Reported either way.
      safeErrorReport(() => onPolicyError?.(err instanceof Error ? err : new Error(String(err)), group.policy))
      const hasDeny = policyHasDenyRule(group.policy)
      perPolicy.push(hasDeny ? false : defaultEffect === 'allow')
      fromDefault.push(!hasDeny)
    }
  }
  if (perPolicy.length === 0) return null
  const result = combine === 'allow-overrides' ? perPolicy.some(Boolean) : perPolicy.every(Boolean)
  if (voteSource) voteSource.fromDefault = result && perPolicy.some((v, i) => v && fromDefault[i] === true)
  return result
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
  onPolicyError?: AccessControl.PolicyErrorHandler,
  voteSource?: IVoteSource,
): boolean | null {
  if (voteSource) voteSource.fromDefault = false
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
  return evaluateDynamicCell(groups, req, defaultEffect, table.policyCombine, caches, onPolicyError, voteSource)
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
  onPolicyError?: AccessControl.PolicyErrorHandler,
  voteSource?: IVoteSource,
): boolean | null {
  if (voteSource) voteSource.fromDefault = false
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
  // per-policy-group handling), so the whole scan resolves Indeterminate rather than
  // risking a partial, order-dependent vote.
  const groups = idx !== undefined ? table.rbacDynamic[idx] : undefined
  if (groups) {
    try {
      for (const g of groups) {
        if ((mask & g.roleMask) === 0) continue
        if (g.scope !== undefined && !scopeCovers(g.scope, req.scope, table.scopeMode)) continue
        // `IAM_RBAC_CONDITION_DEPTH`, not `0`: this group is `perm.conditions` raw,
        // and `rolesToPolicy` nests the same group one level down, so starting at
        // `0` here gave production one nesting level more than development and
        // than `validateRole` allows.
        if (g.conditions && !evalConditionGroup(req, g.conditions, IAM_RBAC_CONDITION_DEPTH, caches)) continue
        return true // role permissions are allow-only - first match wins
      }
    } catch (err) {
      // Indeterminate, not NotApplicable. Role permissions are allow-only, so the
      // vote this scan would have cast is `defaultEffect` - returning `null`
      // abstains and deletes it, which under 'and' turns the throw into an allow.
      safeErrorReport(() => onPolicyError?.(err instanceof Error ? err : new Error(String(err)), groups[0]!.policy))
      if (voteSource) voteSource.fromDefault = true
      return defaultEffect === 'allow'
    }
  }

  // Bound once: the reporter below runs inside a closure, where TypeScript can
  // no longer see that the `if` narrowed away `null`.
  const rbacResidual = table.rbacResidual
  if (rbacResidual) {
    try {
      const vote = evaluatePolicyFast(rbacResidual, req, defaultEffect, caches, voteSource, onPolicyError)
      if (vote !== null) return vote
    } catch (err) {
      // Same Indeterminate contract as every other catch on this path.
      safeErrorReport(() => onPolicyError?.(err instanceof Error ? err : new Error(String(err)), rbacResidual))
      const hasDeny = policyHasDenyRule(rbacResidual)
      if (voteSource) voteSource.fromDefault = !hasDeny
      return hasDeny ? false : defaultEffect === 'allow'
    }
  }

  // No source has a rule shaped for this action/resource. A nonzero grant at this cell
  // (from any role, not just this subject's, via the plain mask or a scoped/conditioned
  // group) means some role's permission does grant this exact pair - just not one this
  // subject holds (or its scope/condition doesn't match) - so that's still a real vote,
  // not silence.
  const hasAnyGrant = cellAllow !== 0 || (groups !== undefined && groups.length > 0)
  if (!hasAnyGrant) return null
  if (voteSource) voteSource.fromDefault = true
  return defaultEffect === 'allow'
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
  onPolicyError?: AccessControl.PolicyErrorHandler,
  signals?: { failOpen?: boolean },
  caches?: Caches,
): boolean {
  const applicable: boolean[] = []
  // Parallel to `applicable`: whether that vote is the `defaultEffect` fallback
  // rather than a rule's verdict. `failOpen` is exactly "the allow rests on the
  // fallback", and the boolean vote alone cannot say so.
  const fromDefault: boolean[] = []
  const voteSource: IVoteSource = { fromDefault: false }
  const push = (vote: boolean | null): void => {
    if (vote === null) return
    applicable.push(vote)
    fromDefault.push(voteSource.fromDefault)
  }

  push(abacFlatVote(table, action, resource, req, defaultEffect, caches, onPolicyError, voteSource))
  push(rbacVote(table, mask, action, resource, req, defaultEffect, caches, onPolicyError, voteSource))

  for (const policy of table.residualPolicies) {
    try {
      push(evaluatePolicyFast(policy, req, defaultEffect, caches, voteSource, onPolicyError))
    } catch (err) {
      // Same Indeterminate contract as the interpreter's safeEval: a deny-bearing
      // policy votes deny, an allow-only one votes `defaultEffect`. Swallowing the
      // error instead drops the vote entirely, which is how a throwing residual
      // policy made production allow what development denied.
      safeErrorReport(() => onPolicyError?.(err instanceof Error ? err : new Error(String(err)), policy))
      const hasDeny = policyHasDenyRule(policy)
      voteSource.fromDefault = !hasDeny
      push(hasDeny ? false : defaultEffect === 'allow')
    }
  }

  if (applicable.length === 0) {
    const allowed = defaultEffect === 'allow'
    if (signals && allowed) signals.failOpen = true
    return allowed
  }
  const allowed = table.policyCombine === 'allow-overrides' ? applicable.some(Boolean) : applicable.every(Boolean)
  // Only the votes that carry the allow count: under `allow-overrides` that is
  // the allowing one, under `and` all of them. Never raised on a deny verdict.
  if (signals && allowed && applicable.some((v, i) => v && fromDefault[i] === true)) signals.failOpen = true
  return allowed
}
