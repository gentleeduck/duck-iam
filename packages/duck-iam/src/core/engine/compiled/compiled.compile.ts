/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { rolesToPolicy } from '../../rbac'
import type { AccessControl } from '../../types'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

/** `roleId`'s bit position is `1 << index`; a 32-bit mask can't address a 33rd role without aliasing an earlier one. */
const MAX_ROLES = 32

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

/** `targets.roles`, or `undefined` when the policy applies regardless of role. */
function targetRolesOf(policy: AccessControl.IPolicy): readonly string[] | undefined {
  return policy.targets?.roles?.length ? policy.targets.roles : undefined
}

/**
 * Action/resource-targeted, or any rule uses a non-literal action/resource - stays out of
 * the flat model. A role-only `targets` restriction IS compilable - see `targetRoles` on
 * `DynamicPolicyGroup`.
 */
function isResidualPolicy(policy: AccessControl.IPolicy): boolean {
  if (policy.targets?.actions?.length || policy.targets?.resources?.length) return true
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

/**
 * Compiles roles + policies into a flat lookup table. RBAC and ABAC are kept as two
 * independently-computed votes combined at request time in `lookup()` - see
 * `compiled.types.ts`'s `rbacResidual` doc for why the two RBAC halves (mask bits +
 * residual policy) must never be treated as separate voters. Wildcard rules and
 * action/resource-targeted policies become residual, evaluated per-request via
 * `evaluatePolicyFast`; role-only-targeted policies compile in (see `isResidualPolicy`).
 */
export function compileTable(
  roles: readonly AccessControl.IRole[],
  policies: readonly AccessControl.IPolicy[],
  policyCombine: AccessControl.PolicyCombine,
): CompiledTable {
  if (roles.length > MAX_ROLES) {
    throw new Error(
      `[@gentleduck/iam:compiled] compileTable(): ${roles.length} roles exceeds the ${MAX_ROLES}-role limit the compiled table's 32-bit grant mask can address without bit-index aliasing (role N and role N+32 would silently share a bit). Reduce the role count, or route this deployment through mode: 'development' instead.`,
    )
  }

  const flatPolicies: AccessControl.IPolicy[] = []
  const residualPolicies: AccessControl.IPolicy[] = []
  for (const policy of policies) {
    if (isResidualPolicy(policy)) residualPolicies.push(policy)
    else flatPolicies.push(policy)
  }

  // RBAC's residual half: same id/inherits/scope so inheritance still resolves,
  // permissions filtered to only the ones that can't take the fast bit path. This is
  // NOT pushed into `residualPolicies` - it is one half of the same logical RBAC vote
  // the `allow` mask bits below are the other half of. See compiled.types.ts.
  const filteredRoles: AccessControl.IRole[] = roles.map((role) => ({
    ...role,
    permissions: role.permissions.filter((perm) => !isSimplePermission(perm, role)),
  }))
  const rbacResidualPolicy = rolesToPolicy(filteredRoles)
  const rbacResidual = rbacResidualPolicy.rules.length > 0 ? rbacResidualPolicy : null

  const hasSimpleRoles = roles.some((role) => role.permissions.some((perm) => isSimplePermission(perm, role)))
  const hasRbacSource = hasSimpleRoles || rbacResidual !== null

  const hasFlatSource = flatPolicies.length > 0

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

  // Populates `allow` (the RBAC grant mask) only - `kind`/`touched` stay purely ABAC
  // territory below; RBAC's vote is computed independently in `lookup()`.
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
    }
  }

  const allowIndices = new Set<number>()
  const denyIndices = new Set<number>()
  // Every rule (conditional or not) touching a cell, grouped per policy - built for every
  // cell so conflicted and forced-'and' cells have real group data to fall back to, not
  // just the conditional ones.
  const groupsByIdx = new Map<number, DynamicPolicyGroup[]>()

  for (const policy of flatPolicies) {
    // Role-targeted: answer depends on the subject's roles, so it can never be a CONST cell.
    const targetRoles = targetRolesOf(policy)
    const policyRules = new Map<number, AccessControl.IRule[]>()
    for (const rule of policy.rules) {
      const conditional = hasConditions(rule.conditions) || targetRoles !== undefined
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
      const group: DynamicPolicyGroup = { policyId: policy.id, algorithm: policy.algorithm, rules, policy, targetRoles }
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

  // A policy that doesn't touch this cell has no rule shaped for it and must not
  // vote here at all (see abacFlatVote's touched===0 -> null) - so only the groups
  // that actually touch a given idx ever combine there. No phantom/forced voters.
  for (const [idx, groups] of groupsByIdx) {
    if (kind[idx] === CellKind.DYNAMIC) dynamic[idx] = groups
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
    dynamic,
    hasFlatSource,
    hasRbacSource,
    rbacResidual,
    residualPolicies,
  }
}

export { CellKind }
