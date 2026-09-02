import { MAX_INHERITANCE_DEPTH } from '../rbac'
import type { AccessControl } from '../types'
import { POLICY_LIMITS, VALID_ALGORITHMS, validateRuleShape } from './validate.libs'
import type { IamValidate } from './validate.types'

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}
/**
 * Validate role defs: duplicate ids, dangling/circular inherits, empty roles.
 *
 * @param roles - The role definitions to validate.
 * @returns A {@link IamValidate.IResult} listing any issues found.
 */
export function validateRoles(roles: readonly AccessControl.IRole[]): IamValidate.IResult {
  const issues: IamValidate.IIssue[] = []
  const roleIds = new Set<string>()

  for (const role of roles) {
    if (roleIds.has(role.id)) {
      issues.push({
        type: 'error',
        code: 'DUPLICATE_ROLE_ID',
        message: `Duplicate role ID "${role.id}"`,
        roleId: role.id,
      })
    }
    roleIds.add(role.id)
  }

  for (const role of roles) {
    for (const parentId of role.inherits ?? []) {
      if (!roleIds.has(parentId)) {
        issues.push({
          type: 'error',
          code: 'DANGLING_INHERIT',
          message: `Role "${role.id}" inherits from "${parentId}" which does not exist`,
          roleId: role.id,
        })
      }
    }
  }

  // Cycles are runtime-safe (handled by visited-set in inheritance walk), so emit as warnings.
  const rolesMap = new Map(roles.map((r) => [r.id, r]))

  for (const role of roles) {
    if (!role.inherits?.length) continue

    const visited = new Set<string>()
    const stack = [role.id]

    while (stack.length > 0) {
      const current = stack.pop()
      if (current === undefined) break
      if (visited.has(current)) {
        issues.push({
          type: 'warning',
          code: 'CIRCULAR_INHERIT',
          message: `Circular inheritance detected involving role "${role.id}" (cycle includes "${current}")`,
          roleId: role.id,
        })
        break
      }
      visited.add(current)

      const r = rolesMap.get(current)
      if (r?.inherits) {
        for (const parentId of r.inherits) {
          if (roleIds.has(parentId)) stack.push(parentId)
        }
      }
    }
  }

  for (const role of roles) {
    if (role.permissions.length === 0 && (!role.inherits || role.inherits.length === 0)) {
      issues.push({
        type: 'warning',
        code: 'EMPTY_ROLE',
        message: `Role "${role.id}" has no permissions and no inheritance`,
        roleId: role.id,
      })
    }
  }

  // Depth bound: chains deeper than MAX_INHERITANCE_DEPTH silently truncate at
  // runtime, dropping permissions invisibly. Surface as error so the operator
  // catches it before deploy instead of debugging missing permissions later.
  for (const role of roles) {
    const depth = longestInheritanceDepth(role.id, rolesMap)
    if (depth > MAX_INHERITANCE_DEPTH) {
      issues.push({
        type: 'error',
        code: 'INHERITANCE_TOO_DEEP',
        message: `Role "${role.id}" has an inheritance chain ${depth} deep; the runtime caps at ${MAX_INHERITANCE_DEPTH} and silently drops anything past it`,
        roleId: role.id,
      })
    }
  }

  return {
    valid: issues.every((i) => i.type !== 'error'),
    issues,
  }
}

/** Longest path from `roleId` up through `inherits`; cycles cut by `seen`, depth capped at `MAX_INHERITANCE_DEPTH + 1`. */
function longestInheritanceDepth(roleId: string, rolesMap: Map<string, AccessControl.IRole>): number {
  const seen = new Set<string>()
  function walk(id: string, depth: number): number {
    if (seen.has(id)) return depth
    if (depth > MAX_INHERITANCE_DEPTH + 1) return depth
    const role = rolesMap.get(id)
    if (!role?.inherits?.length) return depth
    seen.add(id)
    let max = depth
    for (const parent of role.inherits) {
      const d = walk(parent, depth + 1)
      if (d > max) max = d
    }
    seen.delete(id)
    return max
  }
  return walk(roleId, 0)
}

/**
 * A matched target with no matching rule folds `defaultEffect`, which is `deny` - so a
 * target widens what a policy refuses, not only what it inspects. Denying everything it
 * targets is the point of a restrictive policy, so this only fires once the author has
 * written an allow rule and left a pair it can never reach.
 */
function checkTargetIsReachable(p: Record<string, unknown>, issues: IamValidate.IIssue[]): void {
  const targets = p.targets as { actions?: string[]; resources?: string[] } | undefined
  const rules = (Array.isArray(p.rules) ? p.rules : []) as Array<{
    effect?: string
    actions?: string[]
    resources?: string[]
  }>

  if (!targets) return
  const allows = rules.filter((r) => r.effect === 'allow')
  if (allows.length === 0) return

  const covers = (list: string[] | undefined, value: string) =>
    !list || list.length === 0 || list.includes('*') || list.includes(value)

  // A dimension the target omits is one it does not constrain, so the rules decide it.
  // Expanding it to a literal '*' would instead demand every rule be a wildcard: a target
  // naming only `impersonate` was called unreachable because its rule allowed `.of('users')`.
  const actions = targets.actions?.length ? targets.actions : null
  const resources = targets.resources?.length ? targets.resources : null
  if (!actions && !resources) return

  // Same worst-case-cartesian budget used for rules: an oversized target would
  // otherwise push one issue per (action, resource) pair with no cap.
  const pairCount = (actions?.length ?? 1) * (resources?.length ?? 1)
  if (pairCount > POLICY_LIMITS.cartesianPerRule) {
    issues.push({
      type: 'warning',
      code: 'UNREACHABLE_TARGET',
      message: `Target has ${pairCount} (action, resource) pairs, over the ${POLICY_LIMITS.cartesianPerRule} checked for unreachable coverage - skipping the check. Narrow the target to validate it.`,
      path: 'targets',
    })
    return
  }

  for (const action of actions ?? [null]) {
    for (const resource of resources ?? [null]) {
      const reachable = allows.some(
        (r) => (action === null || covers(r.actions, action)) && (resource === null || covers(r.resources, resource)),
      )
      if (reachable) continue

      const pair = resource === null ? `"${action}"` : `"${action ?? '*'}" on "${resource}"`
      issues.push({
        // An error, not a warning, so `PolicyBuilder.build()` throws where the policy is
        // written. A warning read as the permission system working - the visible symptom
        // is a denial - and it cost five separate incidents to recognise. Promoted in
        // 196f52db; see that commit and CHANGELOG's newer "reject a policy whose target
        // names a pair no allow rule covers" entry, not the older "Warning rather than
        // error" entry above it, which documents the since-superseded original behavior.
        type: 'error',
        code: 'UNREACHABLE_TARGET',
        message:
          `Target admits ${pair} but no allow rule covers it, ` +
          'so every request matching it is denied by this policy. Add a rule that allows it, ' +
          'or narrow the target.',
        path: 'targets',
      })
    }
  }
}

/**
 * Deep-validate an untrusted policy (id, name, algorithm, rules, conditions).
 *
 * @param input - The candidate policy object (typically parsed JSON or an admin form payload).
 * @returns A {@link IamValidate.IResult} with `valid: false` when any error issue was emitted.
 */
export function validatePolicy(input: unknown): IamValidate.IResult {
  const issues: IamValidate.IIssue[] = []

  if (!isPlainObject(input)) {
    issues.push({ type: 'error', code: 'INVALID_TYPE', message: 'Policy must be a non-null object', path: '' })
    return { valid: false, issues }
  }

  const p = input

  if (typeof p.id !== 'string' || !p.id) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Policy must have a non-empty string "id"',
      path: 'id',
    })
  }

  if (typeof p.name !== 'string' || !p.name) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Policy must have a non-empty string "name"',
      path: 'name',
    })
  }

  if (typeof p.algorithm !== 'string' || !VALID_ALGORITHMS.has(p.algorithm)) {
    issues.push({
      type: 'error',
      code: 'INVALID_ALGORITHM',
      message: `Invalid algorithm "${String(p.algorithm)}". Must be one of: ${[...VALID_ALGORITHMS].join(', ')}`,
      path: 'algorithm',
    })
  }

  if (p.version !== undefined && typeof p.version !== 'number') {
    issues.push({
      type: 'error',
      code: 'INVALID_TYPE',
      message: '"version" must be a number if provided',
      path: 'version',
    })
  }

  if (!Array.isArray(p.rules)) {
    issues.push({ type: 'error', code: 'MISSING_FIELD', message: 'Policy must have a "rules" array', path: 'rules' })
  } else {
    if (p.rules.length > POLICY_LIMITS.rulesPerPolicy) {
      issues.push({
        type: 'error',
        code: 'LIMIT_EXCEEDED',
        message: `Policy has ${p.rules.length} rules; limit is ${POLICY_LIMITS.rulesPerPolicy}`,
        path: 'rules',
      })
    }
    for (const [i, rule] of p.rules.entries()) {
      validateRuleShape(rule, `rules[${i}]`, issues)
    }

    const ruleIds = new Set<string>()
    for (const rule of p.rules) {
      if (typeof rule !== 'object' || rule === null) continue
      const ruleId = Reflect.get(rule, 'id')
      if (typeof ruleId === 'string') {
        if (ruleIds.has(ruleId)) {
          issues.push({
            type: 'warning',
            code: 'DUPLICATE_RULE_ID',
            message: `Duplicate rule ID "${ruleId}"`,
            path: 'rules',
          })
        }
        ruleIds.add(ruleId)
      }
    }
  }

  if (p.targets !== undefined && p.targets !== null) {
    if (typeof p.targets !== 'object' || Array.isArray(p.targets)) {
      issues.push({
        type: 'error',
        code: 'INVALID_TYPE',
        message: '"targets" must be an object if provided',
        path: 'targets',
      })
    } else {
      const targets = p.targets
      for (const key of ['actions', 'resources', 'roles'] as const) {
        const value = Reflect.get(targets, key)
        if (value !== undefined && !Array.isArray(value)) {
          issues.push({
            type: 'error',
            code: 'INVALID_TYPE',
            message: `targets.${key} must be an array`,
            path: `targets.${key}`,
          })
        }
      }
    }
  }

  checkTargetIsReachable(p, issues)

  return { valid: issues.every((i) => i.type !== 'error'), issues }
}

/**
 * Shape guard for a single Role: `id` non-empty, `permissions` array, optional `inherits: string[]`.
 *
 * @param input - The candidate role object (typically parsed JSON).
 * @returns A {@link IamValidate.IResult} with `valid: false` when any error issue was emitted.
 */
export function validateRole(input: unknown): IamValidate.IResult {
  const issues: IamValidate.IIssue[] = []

  if (!isPlainObject(input)) {
    issues.push({ type: 'error', code: 'INVALID_TYPE', message: 'Role must be a non-null object', path: '' })
    return { valid: false, issues }
  }

  const r = input

  if (typeof r.id !== 'string' || !r.id) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Role must have a non-empty string "id"',
      path: 'id',
    })
  }

  if (!Array.isArray(r.permissions)) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Role must have a "permissions" array',
      path: 'permissions',
    })
  } else {
    // Entries were previously unchecked, so `[null]` or `[{}]` passed validation
    // and reached key building as `undefined:undefined`.
    for (const [i, perm] of r.permissions.entries()) {
      if (!isPlainObject(perm)) {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: `"permissions[${i}]" must be a non-null object`,
          path: `permissions[${i}]`,
        })
        continue
      }
      for (const field of ['action', 'resource'] as const) {
        if (typeof perm[field] !== 'string' || perm[field] === '') {
          issues.push({
            type: 'error',
            code: 'MISSING_FIELD',
            message: `"permissions[${i}].${field}" must be a non-empty string`,
            path: `permissions[${i}].${field}`,
          })
        }
      }
      // `''` is refused, not accepted-and-normalised: the redis encoding spells
      // "no scope" as the empty string, and `matchesScope` used to read an
      // empty pattern as global. One contract - omit the field for global.
      if (perm.scope !== undefined && (typeof perm.scope !== 'string' || perm.scope === '')) {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: `"permissions[${i}].scope" must be a non-empty string if provided (omit it for a global permission)`,
          path: `permissions[${i}].scope`,
        })
      }
      if (perm.conditions !== undefined && !isPlainObject(perm.conditions)) {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: `"permissions[${i}].conditions" must be an object if provided`,
          path: `permissions[${i}].conditions`,
        })
      }
    }
  }

  if (r.inherits !== undefined && r.inherits !== null) {
    if (!Array.isArray(r.inherits)) {
      issues.push({
        type: 'error',
        code: 'INVALID_TYPE',
        message: '"inherits" must be an array of strings if provided',
        path: 'inherits',
      })
    } else {
      for (const [i, v] of r.inherits.entries()) {
        if (typeof v !== 'string') {
          issues.push({
            type: 'error',
            code: 'INVALID_TYPE',
            message: `"inherits[${i}]" must be a string`,
            path: `inherits[${i}]`,
          })
        }
      }
    }
  }

  return { valid: issues.every((i) => i.type !== 'error'), issues }
}

/**
 * Parse a single policy row from `unknown`; returns the typed row or `null` on validation failure.
 *
 * @template TAction   - Action string union (TS-only constraint; trusted at the adapter boundary).
 * @template TResource - Resource string union (TS-only constraint; trusted at the adapter boundary).
 * @template TRole     - Role string union (TS-only constraint; trusted at the adapter boundary).
 */
export function parsePolicyRow<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
>(raw: unknown): AccessControl.IPolicy<TAction, TResource, TRole> | null {
  if (!validatePolicy(raw).valid) return null
  return raw as AccessControl.IPolicy<TAction, TResource, TRole>
}

/** Parse a single role row. Mirror of {@link parsePolicyRow}. */
export function parseRoleRow<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(raw: unknown): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
  if (!validateRole(raw).valid) return null
  return raw as AccessControl.IRole<TAction, TResource, TRole, TScope>
}
