/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { rolesToPolicy } from '../../rbac'
import type { AccessControl } from '../../types'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

/** Not a literal string: `'*'`, or an action/resource prefix pattern (`'foo:*'`, `'foo.*'`). */
function isWildcard(v: string): boolean {
  return v === '*' || v.endsWith(':*') || v.endsWith('.*')
}

function hasConditions(group: AccessControl.IConditionGroup): boolean {
  return 'all' in group
    ? group.all.length > 0
    : 'any' in group
      ? group.any.length > 0
      : 'none' in group
        ? group.none.length > 0
        : false
}

/** targets-scoped, or any rule uses a non-literal action/resource - whole policy stays out of the flat model. */
function isResidualPolicy(policy: AccessControl.IPolicy): boolean {
  if (policy.targets) return true
  for (const rule of policy.rules) {
    for (const a of rule.actions) if (isWildcard(a)) return true
    for (const r of rule.resources) if (isWildcard(r)) return true
  }
  return false
}

/**
 * Eligible for the fast ROLE_MASK bit path: literal action+resource, no conditions, and no
 * scope restriction (permission-level or inherited from the role's default scope) - matches
 * `rolesToPolicy`'s own `perm.scope ?? role.scope` effective-scope rule.
 */
function isSimplePermission(perm: AccessControl.IPermission, role: AccessControl.IRole): boolean {
  if (isWildcard(perm.action) || isWildcard(perm.resource)) return false
  if (perm.conditions && hasConditions(perm.conditions)) return false
  const effectiveScope = perm.scope ?? role.scope
  return effectiveScope === undefined || effectiveScope === '*'
}

/** Compiles roles + policies into a flat lookup table. Everything else (targeted policies, wildcard rules, scoped/conditional role permissions) becomes a residual policy evaluated per-request via `evaluatePolicyFast`. */
export function compileTable(
  roles: readonly AccessControl.IRole[],
  policies: readonly AccessControl.IPolicy[],
  policyCombine: AccessControl.PolicyCombine,
): CompiledTable {
  const flatPolicies: AccessControl.IPolicy[] = []
  const residualPolicies: AccessControl.IPolicy[] = []
  for (const policy of policies) {
    if (isResidualPolicy(policy)) residualPolicies.push(policy)
    else flatPolicies.push(policy)
  }

  // Residual RBAC: same id/inherits/scope so inheritance still resolves, permissions
  // filtered to only the ones that can't take the fast bit path.
  const filteredRoles: AccessControl.IRole[] = roles.map((role) => ({
    ...role,
    permissions: role.permissions.filter((perm) => !isSimplePermission(perm, role)),
  }))
  const rbacResidual = rolesToPolicy(filteredRoles)
  if (rbacResidual.rules.length > 0) residualPolicies.push(rbacResidual)

  const hasSimpleRoles = roles.some((role) => role.permissions.some((perm) => isSimplePermission(perm, role)))
  const totalFlatSources = flatPolicies.length + (hasSimpleRoles ? 1 : 0)
  const forceAndDynamic = policyCombine === 'and' && totalFlatSources > 1
  const foldRbacIntoAnd = forceAndDynamic && hasSimpleRoles
  const hasFlatSource = totalFlatSources > 0

  const actionSet = new Set<string>()
  const resourceSet = new Set<string>()
  for (const role of roles) {
    for (const perm of role.permissions) {
      if (!isSimplePermission(perm, role)) continue
      actionSet.add(perm.action)
      resourceSet.add(perm.resource)
    }
  }
  for (const policy of flatPolicies) {
    for (const rule of policy.rules) {
      for (const a of rule.actions) actionSet.add(a)
      for (const r of rule.resources) resourceSet.add(r)
    }
  }

  const actions = [...actionSet]
  const resources = [...resourceSet]
  const nR = resources.length
  const actionId = new Map(actions.map((a, i) => [a, i]))
  const resourceId = new Map(resources.map((r, i) => [r, i]))
  const roleId = new Map(roles.map((r, i) => [r.id, i]))

  const n = actions.length * nR
  const kind = new Uint8Array(n)
  const touched = new Uint8Array(n)
  const allow = new Uint32Array(n)
  const deny = new Uint32Array(n)
  const dynamic: (readonly DynamicPolicyGroup[] | undefined)[] = new Array(n)

  // holders[roleIdx] = every role whose effective (inherited) set includes roleIdx.
  const byId = new Map(roles.map((r) => [r.id, r]))
  const effective: number[][] = roles.map((r) => {
    const out: number[] = []
    const seen = new Set<string>()
    const walk = (id: string, depth: number): void => {
      if (depth > 32 || seen.has(id)) return
      seen.add(id)
      const idx = roleId.get(id)
      if (idx !== undefined) out.push(idx)
      for (const parent of byId.get(id)?.inherits ?? []) walk(parent, depth + 1)
    }
    walk(r.id, 0)
    return out
  })
  const holders: number[][] = roles.map(() => [])
  for (let i = 0; i < effective.length; i++) {
    for (const a of effective[i]!) {
      holders[a]!.push(i)
    }
  }

  for (let i = 0; i < roles.length; i++) {
    for (const perm of roles[i]!.permissions) {
      if (!isSimplePermission(perm, roles[i]!)) continue
      const a = actionId.get(perm.action)
      const r = resourceId.get(perm.resource)
      if (a === undefined || r === undefined) continue
      const idx = a * nR + r
      let mask = 0
      for (const holder of holders[i]!) mask |= 1 << holder
      allow[idx]! |= mask
      touched[idx] = 1
      if (kind[idx] === CellKind.CONST_DENY) kind[idx] = CellKind.ROLE_MASK
    }
  }

  const allowIndices = new Set<number>()
  const denyIndices = new Set<number>()
  // Every rule (conditional or not) touching a cell, grouped per policy - built for every
  // cell so conflicted and forced-'and' cells have real group data to fall back to, not
  // just the conditional ones.
  const groupsByIdx = new Map<number, DynamicPolicyGroup[]>()

  for (const policy of flatPolicies) {
    const policyRules = new Map<number, AccessControl.IRule[]>()
    for (const rule of policy.rules) {
      const conditional = hasConditions(rule.conditions)
      for (const act of rule.actions) {
        for (const res of rule.resources) {
          const a = actionId.get(act)
          const r = resourceId.get(res)
          if (a === undefined || r === undefined) continue
          const idx = a * nR + r
          touched[idx] = 1
          if (conditional) {
            kind[idx] = CellKind.DYNAMIC
          } else if (rule.effect === 'allow') {
            allowIndices.add(idx)
            if (kind[idx] !== CellKind.DYNAMIC) kind[idx] = CellKind.CONST_ALLOW
          } else {
            denyIndices.add(idx)
          }
          const bucket = policyRules.get(idx)
          if (bucket) bucket.push(rule)
          else policyRules.set(idx, [rule])
        }
      }
    }
    for (const [idx, rules] of policyRules) {
      const group: DynamicPolicyGroup = { policyId: policy.id, algorithm: policy.algorithm, rules }
      const existing = groupsByIdx.get(idx)
      if (existing) existing.push(group)
      else groupsByIdx.set(idx, [group])
    }
  }

  // Conflicting allow+deny on the same cell: becomes DYNAMIC (each policy's own combiner
  // resolves its own rules; cross-policy combine at lookup time resolves the rest) instead
  // of falling through.
  for (const idx of allowIndices) {
    if (denyIndices.has(idx)) kind[idx] = CellKind.DYNAMIC
  }

  if (forceAndDynamic) {
    // Every cell touched by any flat source becomes a mandatory-voter DYNAMIC cell: one
    // group per flatPolicies entry, phantom (`rules: []`) when that policy has none here.
    for (let idx = 0; idx < n; idx++) {
      if (touched[idx] === 0) continue
      kind[idx] = CellKind.DYNAMIC
      const real = groupsByIdx.get(idx)
      dynamic[idx] = flatPolicies.map((policy) => {
        const match = real?.find((g) => g.policyId === policy.id)
        return match ?? { policyId: policy.id, algorithm: policy.algorithm, rules: [] }
      })
    }
  } else {
    for (const [idx, groups] of groupsByIdx) {
      if (kind[idx] === CellKind.DYNAMIC) dynamic[idx] = groups
    }
  }

  return {
    nResources: nR,
    actionId,
    resourceId,
    roleId,
    policyCombine,
    kind,
    touched,
    allow,
    deny,
    dynamic,
    hasFlatSource,
    foldRbacIntoAnd,
    residualPolicies,
  }
}

export { CellKind }
