import type { AccessControl } from '../types'
/**
 * Maximum depth of the inheritance chain walked by {@link collectPermissions}
 * and {@link resolveEffectiveRoles}. Cycles are cut by the `visited` set, but
 * a linear N-deep chain (or a malformed import) would still blow the stack  -
 * the bound makes traversal cost predictable.
 *
 * Roles past this depth are silently dropped from the resolved set. Override
 * is intentionally not exposed: a single hard limit keeps every adapter and
 * validator in agreement. Bump here if your role graph legitimately exceeds 32.
 */
export const MAX_INHERITANCE_DEPTH = 32

/** A permission paired with the role that declared it. */
interface OwnedPermission {
  readonly owner: AccessControl.IRole
  readonly perm: AccessControl.IRole['permissions'][number]
}

/**
 * Flatten role inheritance, returning permissions in parent-first order.
 * Depth is bounded by {@link MAX_INHERITANCE_DEPTH}, and `seen` records the
 * shallowest depth each role was reached at - a role first reached near the cut
 * must not block a later, shallower path from expanding its ancestors, or two
 * set-equal `inherits` arrays in different orders resolve to different
 * permissions. A same-or-deeper re-reach short-circuits, which also cuts cycles.
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

  // Re-reached shallower: its ancestors are expanded again from the new depth,
  // but its own permissions were already emitted on the first visit.
  if (best !== undefined) return inherited

  // Each permission keeps the role that declared it. A permission's scope belongs
  // to its owner, not to whoever inherits it - `compileTable` never flattens the
  // inheritance chain (it walks `role.permissions` and widens the *mask*), so
  // attributing an inherited permission to the inheriting role made the two
  // engines answer differently for the same role graph.
  return [...inherited, ...role.permissions.map((perm) => ({ owner: role, perm }))]
}

/**
 * Id of the single policy `rolesToPolicy` folds every role permission into.
 *
 * Exported because it is not just a label: the evaluator has to be able to tell
 * this policy apart from one an operator authored. It is a union of independent,
 * allow-only grants that the compiled table evaluates first-match-wins, not a
 * single authored unit whose rules are meant to be read together - and that
 * difference decides what happens when one of its rules throws.
 */
export const IAM_RBAC_POLICY_ID = '__rbac__'

/**
 * Depth at which a role permission's own condition group is evaluated.
 *
 * `rolesToPolicy` wraps every permission as `{ all: [{ all: baseConditions }, perm.conditions] }`,
 * so the interpreter's `evalConditionGroup` reaches the author's group one level
 * down. The compiled table stores `perm.conditions` raw and used to start it at
 * `0`, which handed the author ten usable nesting levels in production and nine
 * in development: at exactly `MAX_CONDITION_DEPTH` the table allowed and the
 * interpreter denied. `validateRole` already validates at this depth, so `1` is
 * the number the other two paths were supposed to agree on - the table was the
 * odd one out.
 *
 * Anything that evaluates or checks a permission's conditions outside the
 * generated policy must start here, not at `0`.
 */
export const IAM_RBAC_CONDITION_DEPTH = 1

/**
 * Convert RBAC role definitions into an ABAC policy.
 *
 * Each permission becomes a rule with a condition that checks
 * `subject.roles` contains the role ID. This lets RBAC and ABAC
 * coexist in the same evaluation pipeline.
 *
 * @param roles     - Every role definition (resolved separately of subject assignment).
 * @param scopeMode - `IConfig.scopeMode`. Under `'hierarchical'` a role-declared
 *                    scope covers its descendants, matching what the same flag
 *                    already does for scoped *assignments*; under `'flat'`
 *                    (default) the scope must match exactly.
 * @returns A synthetic {@link AccessControl.IPolicy} with one allow rule per permission.
 */
export function rolesToPolicy(
  roles: AccessControl.IRole[],
  scopeMode: 'flat' | 'hierarchical' = 'flat',
): AccessControl.IPolicy {
  const rolesMap = new Map(roles.map((r) => [r.id, r]))
  const rules: AccessControl.IRule[] = []
  // Monotonic counter for rule ids: stable + unique regardless of role / action
  // / resource names. Previous `rbac.${role}.${action}.${resource}.${i}` format
  // produced ambiguous ids when any segment contained a `.`.
  let ruleSeq = 0

  for (const role of roles) {
    const allPerms = collectPermissions(role.id, rolesMap)

    for (const { owner, perm } of allPerms) {
      const baseConditions: (AccessControl.ICondition | AccessControl.IConditionGroup)[] = [
        { field: 'subject.roles', operator: 'contains' as const, value: role.id },
      ]

      // The scope comes from the role that *declared* the permission. `''` is a
      // scope like any other, not a global: only `undefined` and `'*'` are global,
      // which is what `compiled.compile.ts`'s `effectiveScopeOf` has always said.
      // Testing truthiness here let `scope: ''` grant everywhere in development.
      const effectiveScope = perm.scope ?? owner.scope
      if (effectiveScope !== undefined && effectiveScope !== '*') {
        // Hierarchical scopes are dot-separated paths, so "covers a descendant"
        // is the exact scope or anything under `scope + '.'` - the same relation
        // `scopeAncestors` computes from the other end for scoped assignments.
        // Without this arm one engine flag meant two different things: an
        // assignment at `org-1` reached `org-1.team-a` and an identical
        // role-declared `scope: 'org-1'` did not.
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

      // The author's group is passed through whole and left to
      // `evalConditionGroup`, the one parser that knows which group keys exist.
      // Enumerating `any`/`none` here and falling through to `[]` for the rest
      // dropped an unrecognised group - a typo'd key, a hand-edited row - and a
      // conditional grant silently became unconditional. The shared parser reads
      // an unknown group as `false`, so the grant fails closed instead.
      //
      // The base conditions get their own `all` so the author's group always
      // sits at the same depth whatever its key is. Splicing an `all` body
      // in-line was depth-neutral while `any`/`none` had to be nested, so the
      // identical tree crossed `MAX_CONDITION_DEPTH` in one shape and not the
      // other - and the deeper shape then failed closed at runtime.
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
 * Walks `inherits` chains from each assigned role and returns the closed set
 * of effective role IDs. Cycles are cut by the depth memo; depth is
 * bounded by {@link MAX_INHERITANCE_DEPTH} so a runaway chain can't recurse
 * past the JS stack.
 *
 * An inherited ID that no role in `allRoles` defines is dropped: it would
 * otherwise reach `subject.roles` as a phantom role that no permission backs
 * but an ABAC `subject.roles contains ...` rule still matches. Directly
 * assigned IDs are kept whether or not the catalog defines them.
 *
 * @param assignedRoles Role IDs directly assigned to the subject.
 * @param allRoles      Every role definition, used to resolve `inherits`.
 * @returns Closed set of effective role IDs (assigned + defined inherited).
 */
export function resolveEffectiveRoles(assignedRoles: string[], allRoles: AccessControl.IRole[]): string[] {
  const rolesMap = new Map(allRoles.map((r) => [r.id, r]))
  const effective = new Set<string>()
  // Shallowest depth per role - see `collectPermissions`. `effective` alone
  // cannot serve as the visited set: it would pin a role to whatever depth it
  // was first reached at.
  const bestDepth = new Map<string, number>()

  function walk(roleId: string, depth: number) {
    if (depth > MAX_INHERITANCE_DEPTH) return
    const role = rolesMap.get(roleId)
    // An *inherited* id that no role defines is dropped instead of added. It
    // used to land in `effective` - and so in `subject.roles` - before this
    // lookup ever happened, which made it a phantom role: it carries no
    // permissions, because there is no definition to read any from, but a
    // hand-written ABAC rule testing `subject.roles contains 'ghost'` still
    // fired on it. The operator route into that state is ordinary: delete a
    // role while some other role still names it in `inherits`. `deleteRole`
    // cascades a role's *assignments* on every adapter, so the direct grant
    // goes; the inherited id did not, and the check kept answering allow.
    // `validateRoles` already calls this catalog state `DANGLING_INHERIT` with
    // `type: 'error'`, so dropping it is not a new opinion about the data.
    //
    // Depth 0 is the subject's own assignment and is kept even with no
    // definition behind it. That is a row an operator wrote rather than an id
    // derived from one, and dropping it would silently narrow
    // `getEffectiveRoles` for any deployment where the catalog is not the sole
    // authority on which role ids exist.
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
