import type { AccessControl } from '../types'
/**
 * Max inheritance depth walked by {@link collectPermissions} and {@link resolveEffectiveRoles}.
 * WARN: bounds the resolved role set only; `rolesToPolicy` walks from every role, so a past-cap permission can still be
 * granted. Not configurable, so every adapter and validator agrees on one limit.
 */
export const MAX_INHERITANCE_DEPTH = 32

/** A permission paired with the role that declared it. */
interface OwnedPermission {
  readonly owner: AccessControl.IRole
  readonly perm: AccessControl.IRole['permissions'][number]
}

/**
 * Flatten role inheritance into parent-first permissions, bounded by {@link MAX_INHERITANCE_DEPTH}.
 * NOTE: `seen` keeps each role's shallowest depth so `inherits` order can't change the result; it also cuts cycles.
 */
function collectPermissions(
  roleId: string,
  rolesMap: Map<string, AccessControl.IRole>,
  seen = new Map<string, number>(),
  depth = 0,
): OwnedPermission[] {
  if (depth > MAX_INHERITANCE_DEPTH) return []
  const best = seen.get(roleId)
  if (best !== undefined && best <= depth) return []
  seen.set(roleId, depth)

  const role = rolesMap.get(roleId)
  if (!role) return []

  const inherited = (role.inherits ?? []).flatMap((parent) => collectPermissions(parent, rolesMap, seen, depth + 1))

  // Re-reached shallower: re-expand its ancestors, but its own permissions were already emitted.
  if (best !== undefined) return inherited

  // NOTE: a permission keeps its declaring role, whose scope applies. `compileTable` never flattens inheritance.
  return [...inherited, ...role.permissions.map((perm) => ({ owner: role, perm }))]
}

/**
 * Id of the single policy `rolesToPolicy` folds every role permission into.
 * NOTE: the evaluator uses it to tell these independent allow-only grants from an authored policy when a rule throws.
 */
export const IAM_RBAC_POLICY_ID = '__rbac__'

/**
 * Depth of a role permission's own condition group: `rolesToPolicy` nests it one `all` below the base conditions.
 * WARN: anything checking permission conditions outside the generated policy must start here, not `0`, or the
 * engines disagree at `MAX_CONDITION_DEPTH`.
 */
export const IAM_RBAC_CONDITION_DEPTH = 1

/**
 * Convert RBAC roles into an ABAC policy: each permission becomes a rule gated on `subject.roles` containing the role.
 *
 * @param roles     - Every role definition.
 * @param scopeMode - `IConfig.scopeMode`: `'hierarchical'` lets a role-declared scope cover its descendants, as it
 *                    does for assignments; `'flat'` (default) needs an exact match.
 * @returns A synthetic {@link AccessControl.IPolicy} with one allow rule per permission.
 */
export function rolesToPolicy(
  roles: AccessControl.IRole[],
  scopeMode: 'flat' | 'hierarchical' = 'flat',
): AccessControl.IPolicy {
  const rolesMap = new Map(roles.map((r) => [r.id, r]))
  const rules: AccessControl.IRule[] = []
  // Sequential rule ids stay unique even when role, action, or resource names contain `.`.
  let ruleSeq = 0

  for (const role of roles) {
    const allPerms = collectPermissions(role.id, rolesMap)

    for (const { owner, perm } of allPerms) {
      const baseConditions: (AccessControl.ICondition | AccessControl.IConditionGroup)[] = [
        { field: 'subject.roles', operator: 'contains' as const, value: role.id },
      ]

      // SECURITY: scope comes from the declaring role. Only `undefined` and `'*'` are global, so `''` is a real scope
      // (same as `effectiveScopeOf` in `compiled.compile.ts`); a truthiness test would make `''` grant everywhere.
      const effectiveScope = perm.scope ?? owner.scope
      if (effectiveScope !== undefined && effectiveScope !== '*') {
        // Hierarchical: the exact scope or anything under `scope + '.'`, as `scopeAncestors` does for assignments.
        baseConditions.push(
          scopeMode === 'hierarchical'
            ? {
                any: [
                  { field: 'scope', operator: 'eq' as const, value: effectiveScope },
                  { field: 'scope', operator: 'starts_with' as const, value: `${effectiveScope}.` },
                ],
              }
            : { field: 'scope', operator: 'eq' as const, value: effectiveScope },
        )
      }

      // SECURITY: pass the author's group whole; `evalConditionGroup` reads an unknown group key as `false`.
      // Base conditions get their own `all` so the author's group sits at the same depth whatever its key.
      const conditions = perm.conditions ? { all: [{ all: baseConditions }, perm.conditions] } : { all: baseConditions }

      rules.push({
        id: `__rbac__#${ruleSeq++}`,
        effect: 'allow',
        // The `${role.name}: ` prefix identifies the holder and is filtered on;
        // the inherited-from note goes after it so that prefix stays intact.
        description:
          owner.id === role.id
            ? `${role.name}: ${perm.action} on ${perm.resource}`
            : `${role.name}: ${perm.action} on ${perm.resource} (via ${owner.name})`,
        priority: 10,
        actions: [perm.action],
        resources: [perm.resource],
        conditions,
      })
    }
  }

  return {
    id: IAM_RBAC_POLICY_ID,
    name: 'RBAC Policies',
    description: 'Auto-generated from role definitions',
    algorithm: 'allow-overrides',
    rules,
  }
}

/**
 * Walk `inherits` from each assigned role into the closed set of effective role IDs, bounded by
 * {@link MAX_INHERITANCE_DEPTH}. Inherited IDs with no definition are dropped; assigned IDs are kept.
 *
 * @param assignedRoles Role IDs directly assigned to the subject.
 * @param allRoles      Every role definition, used to resolve `inherits`.
 * @returns Closed set of effective role IDs (assigned + defined inherited).
 */
export function resolveEffectiveRoles(assignedRoles: string[], allRoles: AccessControl.IRole[]): string[] {
  const rolesMap = new Map(allRoles.map((r) => [r.id, r]))
  const effective = new Set<string>()
  // NOTE: shallowest depth per role (see `collectPermissions`). `effective` can't be the visited set: it would pin a
  // role to the depth it was first reached at.
  const bestDepth = new Map<string, number>()

  function walk(roleId: string, depth: number) {
    if (depth > MAX_INHERITANCE_DEPTH) return
    const role = rolesMap.get(roleId)
    // SECURITY: drop an inherited id with no definition (a `DANGLING_INHERIT`, e.g. a deleted role still inherited), or
    // it matches ABAC `subject.roles contains` rules as a phantom. Depth 0 is an operator-written assignment: keep it.
    if (role === undefined && depth > 0) return
    const best = bestDepth.get(roleId)
    if (best !== undefined && best <= depth) return
    bestDepth.set(roleId, depth)
    effective.add(roleId)
    for (const parent of role?.inherits ?? []) walk(parent, depth + 1)
  }

  for (const r of assignedRoles) walk(r, 0)
  return [...effective]
}
