/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */

import { matchesUnconditionally } from '../../conditions/conditions'
import { combiners, policyTargetsActionResource } from '../../evaluate/evaluate.libs'
import { MAX_INHERITANCE_DEPTH, rolesToPolicy } from '../../rbac'
import type { AccessControl } from '../../types'
import { IAM_MAX_COMPILED_ROLES as MAX_ROLES } from '../engine.libs'
import { IamPolicyCompileError, IamRoleLimitExceededError } from './compiled.errors'
import { CellKind, type CompiledTable, type DynamicPolicyGroup, type RbacRuleGroup } from './compiled.types'

/** Not a literal string: `'*'`, or an action/resource prefix pattern (`'foo:*'`, `'foo.*'`). */
function isWildcard(v: string): boolean {
  return v === '*' || v.endsWith(':*') || v.endsWith('.*')
}

/**
 * True when the group is anything other than a request-independent match, so
 * the rule cannot be lowered into a static cell. This is deliberately wider
 * than "carries a clause": a group that can never match (`{ any: [] }`, an
 * unrecognised key set) is not static-true either, and treating it as one
 * lowered a rule the interpreter refuses into a cell that always fires.
 */
function hasConditions(group: AccessControl.IConditionGroup): boolean {
  return !matchesUnconditionally(group)
}

/** `targets.roles`, or `undefined` when the policy applies regardless of role. */
function targetRolesOf(policy: AccessControl.IPolicy): readonly string[] | undefined {
  return policy.targets?.roles?.length ? policy.targets.roles : undefined
}

/**
 * Reject a policy whose shape the compiler cannot walk, naming it.
 *
 * Runs before anything reads `policy.rules`, so a malformed policy fails here
 * - attributed - instead of somewhere downstream as an anonymous
 * `rules is not iterable`. The engine forwards this to `onPolicyError` with the
 * id and rethrows; the deny is unchanged. See {@link IamPolicyCompileError}.
 *
 * The checks are the fields the compiler actually iterates. Types claim all
 * three are arrays, which is exactly the claim that does not survive a policy
 * arriving from an adapter, a database row, or a hand-written config.
 */
function assertCompilablePolicy(policy: AccessControl.IPolicy): void {
  const policyId = typeof policy.id === 'string' ? policy.id : '<unnamed>'
  if (!Array.isArray(policy.rules)) throw new IamPolicyCompileError(policyId, '`rules` is missing or not an array')
  let index = 0
  for (const rule of policy.rules) {
    const at = typeof rule?.id === 'string' ? `rule ${JSON.stringify(rule.id)}` : `rule at index ${index}`
    index++
    if (rule === null || typeof rule !== 'object') throw new IamPolicyCompileError(policyId, `${at} is not an object`)
    if (!Array.isArray(rule.actions)) throw new IamPolicyCompileError(policyId, `${at}: \`actions\` is not an array`)
    if (!Array.isArray(rule.resources))
      throw new IamPolicyCompileError(policyId, `${at}: \`resources\` is not an array`)
  }
}

/**
 * A rule with a non-literal (wildcard/prefix) action or resource, or a `targets.actions`/
 * `targets.resources` value that is itself a wildcard, stays out of the flat model - it could
 * match requests no rule was ever literally indexed for, so it can't be reduced to fixed
 * cells. A LITERAL `targets.actions`/`targets.resources` restriction IS compilable: unlike
 * roles, it doesn't depend on who's asking - only on the (action, resource) pair, which is
 * already the cell's own key - see `policyTargetsActionResource`, applied per-rule below. A
 * role-only `targets` restriction is compilable too, regardless - see `targetRoles` on
 * `DynamicPolicyGroup`.
 */
function isResidualPolicy(policy: AccessControl.IPolicy): boolean {
  // An unrecognised algorithm cannot be reduced to cells: cell kind is decided
  // from `rule.effect` alone, so a deny-carrying policy would compile to a
  // CONST_ALLOW and grant in production while the interpreter throws and denies.
  // Residual keeps it on `evaluatePolicyFast`, which rejects it the same way.
  if (!Object.hasOwn(combiners, policy.algorithm)) return true
  if (policy.targets?.actions?.some(isWildcard) || policy.targets?.resources?.some(isWildcard)) return true
  for (const rule of policy.rules) {
    for (const a of rule.actions) if (isWildcard(a)) return true
    for (const r of rule.resources) if (isWildcard(r)) return true
  }
  return false
}

/** A wildcarded action or resource can't be reduced to fixed cells - stays fully in `rbacResidual` regardless of scope/conditions. */
function isWildcardPermission(perm: AccessControl.IPermission): boolean {
  return isWildcard(perm.action) || isWildcard(perm.resource)
}

/** `perm.scope ?? role.scope`, excluding the global markers (`undefined`/`'*'`). Matches `rolesToPolicy`'s own effective-scope rule. */
function effectiveScopeOf(perm: AccessControl.IPermission, role: AccessControl.IRole): string | undefined {
  const effectiveScope = perm.scope ?? role.scope
  return effectiveScope === undefined || effectiveScope === '*' ? undefined : effectiveScope
}

/**
 * Eligible for the fast ROLE_MASK bit path: literal action+resource, no conditions, and no
 * scope restriction (permission-level or inherited from the role's default scope).
 */
function isSimplePermission(perm: AccessControl.IPermission, role: AccessControl.IRole): boolean {
  if (isWildcardPermission(perm)) return false
  if (perm.conditions && hasConditions(perm.conditions)) return false
  return effectiveScopeOf(perm, role) === undefined
}

/**
 * Compiles roles + policies into a flat lookup table. RBAC and ABAC are kept as two
 * independently-computed votes combined at request time in `lookup()` - see
 * `compiled.types.ts`'s `rbacResidual` doc for why the two RBAC halves (mask bits +
 * residual policy) must never be treated as separate voters. A wildcard rule, or a
 * wildcarded `targets.actions`/`targets.resources` value, keeps a policy residual, evaluated
 * per-request via `evaluatePolicyFast`; a literal target restriction (action, resource,
 * and/or role) compiles in instead (see `isResidualPolicy`).
 */
export function compileTable(
  roles: readonly AccessControl.IRole[],
  policies: readonly AccessControl.IPolicy[],
  policyCombine: AccessControl.PolicyCombine,
  scopeMode: 'flat' | 'hierarchical' = 'flat',
): CompiledTable {
  if (roles.length > MAX_ROLES) {
    throw new IamRoleLimitExceededError(roles.length, MAX_ROLES)
  }

  const flatPolicies: AccessControl.IPolicy[] = []
  const residualPolicies: AccessControl.IPolicy[] = []
  for (const policy of policies) {
    assertCompilablePolicy(policy)
    if (isResidualPolicy(policy)) residualPolicies.push(policy)
    else flatPolicies.push(policy)
  }

  // RBAC's residual source: same id/inherits/scope so inheritance still resolves,
  // permissions filtered to the ones that can't be reduced to fixed cells at all
  // (wildcarded action/resource). This is NOT pushed into `residualPolicies` - it is one
  // of three sources of the same logical RBAC vote (see compiled.types.ts).
  const filteredRoles: AccessControl.IRole[] = roles.map((role) => ({
    ...role,
    permissions: role.permissions.filter((perm) => isWildcardPermission(perm)),
  }))
  const rbacResidualPolicy = rolesToPolicy(filteredRoles, scopeMode)
  const rbacResidual = rbacResidualPolicy.rules.length > 0 ? rbacResidualPolicy : null

  // RBAC's cell-dynamic source: literal action+resource, but scope and/or conditions. This
  // synthetic policy is never evaluated directly - it exists only so a rotten condition can
  // be reported via onPolicyError (mirrors DynamicPolicyGroup.policy), shared by every group.
  const dynamicSourceRoles: AccessControl.IRole[] = roles.map((role) => ({
    ...role,
    permissions: role.permissions.filter((perm) => !isWildcardPermission(perm) && !isSimplePermission(perm, role)),
  }))
  const rbacDynamicSourcePolicy = rolesToPolicy(dynamicSourceRoles, scopeMode)
  const hasRbacDynamic = rbacDynamicSourcePolicy.rules.length > 0

  const hasSimpleRoles = roles.some((role) => role.permissions.some((perm) => isSimplePermission(perm, role)))
  const hasRbacSource = hasSimpleRoles || hasRbacDynamic || rbacResidual !== null

  const hasFlatSource = flatPolicies.length > 0

  const actionSet = new Set<string>()
  const resourceSet = new Set<string>()
  for (const role of roles) {
    for (const perm of role.permissions) {
      if (isWildcardPermission(perm)) continue
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
    // Shallowest depth per role, and `MAX_INHERITANCE_DEPTH` rather than a bare
    // 32, so this walk cannot drift from the interpreter's in either respect.
    const seen = new Map<string, number>()
    const walk = (id: string, depth: number): void => {
      if (depth > MAX_INHERITANCE_DEPTH) return
      const best = seen.get(id)
      if (best !== undefined && best <= depth) return
      if (best === undefined) {
        const idx = roleId.get(id)
        if (idx !== undefined) out.push(idx)
      }
      seen.set(id, depth)
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

  // Populates `allow` (the RBAC grant mask) and `rbacDynamic` (scope/condition-restricted
  // permissions) only - `kind`/`touched` stay purely ABAC territory below; RBAC's vote is
  // computed independently in `lookup()`.
  const rbacDynamicGroupsByIdx = new Map<number, RbacRuleGroup[]>()
  for (let i = 0; i < roles.length; i++) {
    const role = roles[i]!
    for (const perm of role.permissions) {
      if (isWildcardPermission(perm)) continue // stays fully in rbacResidual, no cell
      const a = actionId.get(perm.action)
      const r = resourceId.get(perm.resource)
      if (a === undefined || r === undefined) continue
      const idx = a * nR + r
      let mask = 0
      for (const holder of holders[i]!) mask |= 1 << holder

      if (isSimplePermission(perm, role)) {
        allow[idx]! |= mask
        continue
      }

      const group: RbacRuleGroup = {
        roleMask: mask,
        scope: effectiveScopeOf(perm, role),
        conditions: perm.conditions,
        policy: rbacDynamicSourcePolicy,
      }
      const bucket = rbacDynamicGroupsByIdx.get(idx)
      if (bucket) bucket.push(group)
      else rbacDynamicGroupsByIdx.set(idx, [group])
    }
  }
  const rbacDynamic: (readonly RbacRuleGroup[] | undefined)[] = new Array(n)
  for (const [idx, groups] of rbacDynamicGroupsByIdx) rbacDynamic[idx] = groups

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
          // A literal targets.actions/targets.resources restriction filters which cells this
          // rule reaches - same as policyApplies()'s action/resource check in the interpreter,
          // just resolved once here instead of on every request.
          if (!policyTargetsActionResource(policy, act, res)) continue
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
    scopeMode,
    kind,
    touched,
    allow,
    dynamic,
    rbacDynamic,
    hasFlatSource,
    hasRbacSource,
    rbacResidual,
    residualPolicies,
  }
}

export { CellKind }
