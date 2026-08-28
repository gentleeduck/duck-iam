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
      // Rotten rule drops its policy as NotApplicable, same as evaluateFast's safeEval.
    }
  }
  if (perPolicy.length === 0) return defaultEffect === 'allow'
  if (policyCombine === 'allow-overrides') return perPolicy.some(Boolean)
  return perPolicy.every(Boolean)
}

/** `'fallthrough'` means compileTable() never touched this cell — route to evaluateFast. */
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

/** Applies `(base | scopeAllow) & ~scopeDeny` before `lookup()`, so ROLE_MASK and DYNAMIC cells both get scope for free. */
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
