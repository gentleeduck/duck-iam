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
 * Folds one DYNAMIC ABAC cell's per-policy votes into one boolean; `null` when no group applies to the subject.
 * SECURITY: a throw is Indeterminate, never an abstain: deny if the policy has a deny rule, else `defaultEffect`.
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
  // Parallel to `perPolicy`: whether that group's allow came from `defaultEffect`, not a rule that fired.
  const fromDefault: boolean[] = []
  const subjectRoles = Array.isArray(req.subject.roles) ? req.subject.roles : []
  for (const group of groups) {
    // A subject without a targeted role gets no vote from the group, as in policyApplies().
    if (group.targetRoles && !group.targetRoles.some((r) => subjectRoles.includes(r))) continue
    try {
      const matched = group.rules
        .filter((rule) => evalConditionGroup(req, rule.conditions, 0, caches))
        .map((rule) => ({ rule, effect: rule.effect }))
      // NOTE: `isResidualPolicy` keeps an unknown or inherited algorithm out of the table, so this index is
      // always an own property; `evaluatePolicyFast` is what refuses one.
      const decision = combiners[group.algorithm](matched, defaultEffect)
      perPolicy.push(decision.effect === 'allow')
      fromDefault.push(decision.rule === undefined)
    } catch (err) {
      // WARN: ask the whole policy, as the interpreter does, not `group.rules`, which holds only this cell's rules.
      safeErrorReport(onPolicyError, err, group.policy)
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
 * The ABAC flat layer's vote at one cell. `null` when no flat policy has a rule for this action and resource,
 * or when no DYNAMIC group applies to the subject.
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
 * RBAC's single vote, OR'd over `allow`, `rbacDynamic` and `rbacResidual`. A miss votes `defaultEffect` only when
 * some role grants this exact pair; otherwise `null`. See `CompiledTable.rbacResidual` for why it is ONE vote.
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

  // NOTE: `actionId`/`resourceId` are shared with ABAC, so a known dimension does not mean some role grants it.
  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  const idx = a !== undefined && r !== undefined ? a * table.nResources + r : undefined
  const cellAllow = idx !== undefined ? table.allow[idx]! : 0
  if ((mask & cellAllow) !== 0) return true

  // Scoped/conditioned grants, caught per group so one bad permission skips only itself (as `rulesAbstainOnThrow`).
  // NOTE: abstaining per grant loses no deny, because role permissions are allow-only.
  const groups = idx !== undefined ? table.rbacDynamic[idx] : undefined
  if (groups) {
    for (const g of groups) {
      if ((mask & g.roleMask) === 0) continue
      if (g.scope !== undefined && !scopeCovers(g.scope, req.scope, table.scopeMode)) continue
      try {
        // NOTE: not depth `0`: `rolesToPolicy` nests `perm.conditions` one level down, and the limits must match.
        if (g.conditions && !evalConditionGroup(req, g.conditions, IAM_RBAC_CONDITION_DEPTH, caches)) continue
      } catch (err) {
        safeErrorReport(onPolicyError, err, g.policy)
        continue
      }
      return true // role permissions are allow-only - first match wins
    }
  }

  // Bound to a local so the narrowing from `null` survives into the catch.
  const rbacResidual = table.rbacResidual
  if (rbacResidual) {
    try {
      const vote = evaluatePolicyFast(rbacResidual, req, defaultEffect, caches, voteSource, onPolicyError)
      if (vote !== null) return vote
    } catch (err) {
      // Same Indeterminate contract as every other catch on this path.
      safeErrorReport(onPolicyError, err, rbacResidual)
      const hasDeny = policyHasDenyRule(rbacResidual)
      if (voteSource) voteSource.fromDefault = !hasDeny
      return hasDeny ? false : defaultEffect === 'allow'
    }
  }

  // No source matched. A grant here held by any role, even one this subject lacks, still makes this a real vote.
  // SECURITY: skip `roleMask === 0` groups (shadowed duplicate role ids); counting them fails open on default allow.
  const hasAnyGrant = cellAllow !== 0 || groups?.some((g) => g.roleMask !== 0) === true
  if (!hasAnyGrant) return null
  if (voteSource) voteSource.fromDefault = true
  return defaultEffect === 'allow'
}

/**
 * Answers every request, with no fallthrough: combines the ABAC flat vote, the RBAC vote and each residual policy.
 * Mirrors `evaluateFast`'s combine, error handling and `failOpen` signal.
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
  // Parallel to `applicable`: whether that vote is the `defaultEffect` fallback, which is what `failOpen` reports.
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
      // SECURITY: Indeterminate, as in the interpreter's safeEval. Dropping the vote would let production over-allow.
      safeErrorReport(onPolicyError, err, policy)
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
  // NOTE: 'first-applicable' would fold as 'and' (stricter); `IamEngine._getCompiledTable` keeps it off this path.
  const allowed = table.policyCombine === 'allow-overrides' ? applicable.some(Boolean) : applicable.every(Boolean)
  // Only votes that carry the allow count toward `failOpen`; never raised on a deny.
  if (signals && allowed && applicable.some((v, i) => v && fromDefault[i] === true)) signals.failOpen = true
  return allowed
}
