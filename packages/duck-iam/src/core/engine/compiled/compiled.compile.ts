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
 * True unless the group matches every request unconditionally, so the rule cannot become a static cell.
 * SECURITY: wider than "has a clause": a never-matching group (`{ any: [] }`, unknown keys) is not static-true either.
 */
function hasConditions(group: AccessControl.IConditionGroup): boolean {
  return !matchesUnconditionally(group)
}

/** `targets.roles`, or `undefined` when the policy applies regardless of role. */
function targetRolesOf(policy: AccessControl.IPolicy): readonly string[] | undefined {
  return policy.targets?.roles?.length ? policy.targets.roles : undefined
}

/**
 * Rejects, by policy id, a shape the compiler cannot walk: `rules`, `actions` or `resources` not an array.
 * Runs first, since adapter rows and hand-written configs do not honour the types. See {@link IamPolicyCompileError}.
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
 * True when a policy must stay out of the flat model: an unknown algorithm, or a wildcard/prefix action or resource
 * in a rule or in `targets`, which matches unindexed requests. Literal and role-only `targets` still compile.
 */
function isResidualPolicy(policy: AccessControl.IPolicy): boolean {
  // SECURITY: cell kind comes from `rule.effect` alone, so an unknown algorithm could compile a deny-carrying
  // policy to CONST_ALLOW. `evaluatePolicyFast` rejects it the way the interpreter does.
  if (!Object.hasOwn(combiners, policy.algorithm)) return true
  if (policy.targets?.actions?.some(isWildcard) || policy.targets?.resources?.some(isWildcard)) return true
  for (const rule of policy.rules) {
    for (const a of rule.actions) if (isWildcard(a)) return true
    for (const r of rule.resources) if (isWildcard(r)) return true
  }
  return false
}

/** A wildcarded action or resource cannot become fixed cells, so the permission stays in `rbacResidual`. */
function isWildcardPermission(perm: AccessControl.IPermission): boolean {
  return isWildcard(perm.action) || isWildcard(perm.resource)
}

/** `perm.scope ?? role.scope`, with `'*'` read as unscoped, matching `rolesToPolicy`. */
function effectiveScopeOf(perm: AccessControl.IPermission, role: AccessControl.IRole): string | undefined {
  const effectiveScope = perm.scope ?? role.scope
  return effectiveScope === undefined || effectiveScope === '*' ? undefined : effectiveScope
}

/** Eligible for the `allow` mask bit: literal action and resource, no conditions, no effective scope. */
function isSimplePermission(perm: AccessControl.IPermission, role: AccessControl.IRole): boolean {
  if (isWildcardPermission(perm)) return false
  if (perm.conditions && hasConditions(perm.conditions)) return false
  return effectiveScopeOf(perm, role) === undefined
}

/**
 * Compiles roles and policies into a flat lookup table. ABAC and RBAC stay separate votes, combined in `lookup()`.
 * Throws {@link IamRoleLimitExceededError} past the role cap and {@link IamPolicyCompileError} on a malformed policy.
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

  // RBAC's residual source: only wildcarded permissions, with ids/inherits/scope kept so inheritance resolves.
  // Not in `residualPolicies`: it is one of three sources of the single RBAC vote (see compiled.types.ts).
  const filteredRoles: AccessControl.IRole[] = roles.map((role) => ({
    ...role,
    permissions: role.permissions.filter((perm) => isWildcardPermission(perm)),
  }))
  const rbacResidualPolicy = rolesToPolicy(filteredRoles, scopeMode)
  const rbacResidual = rbacResidualPolicy.rules.length > 0 ? rbacResidualPolicy : null

  // RBAC's cell-dynamic source: literal permissions with a scope or conditions. The policy is never evaluated;
  // every group shares it so a bad condition can be reported via onPolicyError.
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
    // NOTE: shallowest depth per role and `MAX_INHERITANCE_DEPTH`, so this walk matches the interpreter's.
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

  // Fills only `allow` and `rbacDynamic`; `kind`/`touched` stay ABAC-only, and RBAC votes separately in `lookup()`.
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
  // Every rule touching a cell, conditional or not, grouped per policy, so conflicted cells have groups too.
  const groupsByIdx = new Map<number, DynamicPolicyGroup[]>()

  for (const policy of flatPolicies) {
    // Role-targeted: answer depends on the subject's roles, so it can never be a CONST cell.
    const targetRoles = targetRolesOf(policy)
    const policyRules = new Map<number, AccessControl.IRule[]>()
    for (const rule of policy.rules) {
      const conditional = hasConditions(rule.conditions) || targetRoles !== undefined
      for (const act of rule.actions) {
        for (const res of rule.resources) {
          // Literal targets.actions/resources, resolved once here instead of per request as in policyApplies().
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

  // Allow and deny on one cell: DYNAMIC, so each policy's combiner and then the cross-policy combine decide.
  for (const idx of allowIndices) {
    if (denyIndices.has(idx)) kind[idx] = CellKind.DYNAMIC
  }

  // Only policies with a rule at this cell vote here (see abacFlatVote's `touched === 0` -> null).
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
