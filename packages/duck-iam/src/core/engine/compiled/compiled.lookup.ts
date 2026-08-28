/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { evalConditionGroup } from '../../conditions'
import { combiners } from '../../evaluate/evaluate.libs'
import type { AccessControl, IamRequest } from '../../types'
import { resolveScopeMask, type ScopeMask } from './compiled.scope'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

function evaluateDynamicCell(
  groups: readonly DynamicPolicyGroup[],
  req: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect,
  policyCombine: AccessControl.PolicyCombine,
): boolean {
  const perPolicy: boolean[] = []
  for (const group of groups) {
    try {
      const matched = group.rules
        .filter((rule) => evalConditionGroup(req, rule.conditions, 0))
        .map((rule) => ({ rule, effect: rule.effect }))
      const decision = combiners[group.algorithm](matched, defaultEffect)
      perPolicy.push(decision.effect === 'allow')
    } catch {
      // A single rotten rule (regex-too-large, etc.) drops its policy as
      // NotApplicable, same as evaluateFast's safeEval — never poisons the
      // whole cell.
    }
  }
  if (perPolicy.length === 0) return defaultEffect === 'allow'
  if (policyCombine === 'allow-overrides') return perPolicy.some(Boolean)
  return perPolicy.every(Boolean) // 'and' (and 'first-applicable', blocked at Engine construction in production)
}

/**
 * Phase 2 lookup. `req` is required once a cell can be DYNAMIC; omit it only
 * when the caller already knows every cell it queries is CONST/ROLE_MASK.
 * Returns `'fallthrough'` for any cell compileTable() never touched.
 */
export function lookup(
  table: CompiledTable,
  mask: number,
  action: string,
  resource: string,
  req?: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  policyCombine: AccessControl.PolicyCombine = 'and',
): boolean | 'fallthrough' {
  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  if (a === undefined || r === undefined) return 'fallthrough'
  const idx = a * table.nResources + r
  if (table.touched[idx] === 0) return 'fallthrough'
  const k = table.kind[idx]
  if (k === CellKind.CONST_ALLOW) return true
  if (k === CellKind.CONST_DENY) return false
  if (k === CellKind.ROLE_MASK) return (mask & table.allow[idx]!) !== 0
  // DYNAMIC
  if ((mask & table.allow[idx]!) !== 0) return true // role-bypass fast path
  const groups = table.dynamic[idx]
  if (!groups || req === undefined) return 'fallthrough'
  return evaluateDynamicCell(groups, req, defaultEffect, policyCombine)
}

/**
 * Resolves the scope overlay `(base | scopeAllow) & ~scopeDeny` before
 * calling `lookup()`, so ROLE_MASK and DYNAMIC cells both get scope for
 * free without their own scope-aware branch. `scopeDeny` gates the whole
 * cell outright, including DYNAMIC's role-bypass fast path and its rule
 * closures - scope narrows what role-bits reach a cell, it never bypasses
 * a real ABAC condition. See engine-rewrite.md, "Hierarchical scope."
 */
export function lookupScoped(
  table: CompiledTable,
  baseMask: number,
  scopeTrie: ReadonlyMap<string, ScopeMask> | null | undefined,
  scope: string | undefined,
  scopeCombine: 'union' | 'override',
  action: string,
  resource: string,
  req?: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  policyCombine: AccessControl.PolicyCombine = 'and',
): boolean | 'fallthrough' {
  let mask = baseMask
  if (scopeTrie && scope != null) {
    const { allow: scopeAllow, deny: scopeDeny } = resolveScopeMask(scopeTrie, scope, scopeCombine)
    mask = (mask | scopeAllow) & ~scopeDeny
  }
  return lookup(table, mask, action, resource, req, defaultEffect, policyCombine)
}
