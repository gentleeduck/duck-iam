/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import type { AccessControl } from '../../types'
import { CellKind, type CompiledTable, type DynamicPolicyGroup } from './compiled.types'

function isWildcard(v: string): boolean {
  return v === '*'
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

/**
 * Compiles roles + policies into a flat lookup table. Excludes: wildcard
 * action/resource rules, and any policy with `targets` set — both fall
 * through to `evaluateFast` unchanged (see engine-rewrite.md, "What phase 4
 * does not attempt").
 */
export function compileTable(
  roles: readonly AccessControl.IRole[],
  policies: readonly AccessControl.IPolicy[],
): CompiledTable {
  const actionSet = new Set<string>()
  const resourceSet = new Set<string>()
  for (const role of roles) {
    for (const p of role.permissions) {
      if (!isWildcard(p.action)) actionSet.add(p.action)
      if (!isWildcard(p.resource)) resourceSet.add(p.resource)
    }
  }
  for (const policy of policies) {
    if (policy.targets) continue
    for (const rule of policy.rules) {
      for (const a of rule.actions) if (!isWildcard(a)) actionSet.add(a)
      for (const r of rule.resources) if (!isWildcard(r)) resourceSet.add(r)
    }
  }

  const actions = [...actionSet]
  const resources = [...resourceSet]
  const nR = resources.length
  const actionId = new Map(actions.map((a, i) => [a, i]))
  const resourceId = new Map(resources.map((r, i) => [r, i]))
  const roleId = new Map(roles.map((r, i) => [r.id, i]))

  const kind = new Uint8Array(actions.length * nR)
  const touched = new Uint8Array(actions.length * nR)
  const allow = new Uint32Array(actions.length * nR)
  const deny = new Uint32Array(actions.length * nR)
  const dynamic: (readonly DynamicPolicyGroup[] | undefined)[] = new Array(actions.length * nR)

  // Close inheritance once; invert to holders[roleIdx] = every role whose
  // effective set contains roleIdx (same rule resolveEffectiveRoles uses).
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
      if (isWildcard(perm.action) || isWildcard(perm.resource)) continue
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

  // Track cells touched by allow and deny rules to detect conflicts
  const allowIndices = new Set<number>()
  const denyIndices = new Set<number>()

  for (const policy of policies) {
    if (policy.targets) continue
    for (const rule of policy.rules) {
      if (hasConditions(rule.conditions)) continue // DYNAMIC cells: Task 3
      for (const act of rule.actions) {
        if (isWildcard(act)) continue
        for (const res of rule.resources) {
          if (isWildcard(res)) continue
          const a = actionId.get(act)
          const r = resourceId.get(res)
          if (a === undefined || r === undefined) continue
          const idx = a * nR + r
          touched[idx] = 1
          if (rule.effect === 'allow') {
            allowIndices.add(idx)
            if (kind[idx] !== CellKind.DYNAMIC) kind[idx] = CellKind.CONST_ALLOW
          } else if (rule.effect === 'deny') {
            denyIndices.add(idx)
          }
        }
      }
    }
  }

  // Force conflicted cells (both allow and deny touched) to untouched to fall through to evaluateFast
  for (const idx of allowIndices) {
    if (denyIndices.has(idx)) {
      touched[idx] = 0
    }
  }

  return { nResources: nR, actionId, resourceId, roleId, kind, touched, allow, deny, dynamic }
}

export { CellKind }
