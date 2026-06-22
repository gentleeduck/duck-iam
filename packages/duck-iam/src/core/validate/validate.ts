import { IAM_MAX_INHERITANCE_DEPTH } from '../rbac'
import type { IamAccessControl } from '../types'
import { IAM_POLICY_LIMITS, IAM_VALID_ALGORITHMS, validateRuleShape } from './validate.libs'
import type { IamValidate } from './validate.types'

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}
/**
 * IamValidate role defs: duplicate ids, dangling/circular inherits, empty roles.
 *
 * @param roles - The role definitions to validate.
 * @returns A {@link IamValidate.IResult} listing any issues found.
 */
export function iamValidateRoles(roles: readonly IamAccessControl.IRole[]): IamValidate.IResult {
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

  // Depth bound: chains deeper than IAM_MAX_INHERITANCE_DEPTH silently truncate at
  // runtime, dropping permissions invisibly. Surface as error so the operator
  // catches it before deploy instead of debugging missing permissions later.
  for (const role of roles) {
    const depth = longestInheritanceDepth(role.id, rolesMap)
    if (depth > IAM_MAX_INHERITANCE_DEPTH) {
      issues.push({
        type: 'error',
        code: 'INHERITANCE_TOO_DEEP',
        message: `Role "${role.id}" has an inheritance chain ${depth} deep; the runtime caps at ${IAM_MAX_INHERITANCE_DEPTH} and silently drops anything past it`,
        roleId: role.id,
      })
    }
  }

  return {
    valid: issues.every((i) => i.type !== 'error'),
    issues,
  }
}

/** Longest path from `roleId` up through `inherits`; cycles cut by `seen`, depth capped at `IAM_MAX_INHERITANCE_DEPTH + 1`. */
function longestInheritanceDepth(roleId: string, rolesMap: Map<string, IamAccessControl.IRole>): number {
  const seen = new Set<string>()
  function walk(id: string, depth: number): number {
    if (seen.has(id)) return depth
    if (depth > IAM_MAX_INHERITANCE_DEPTH + 1) return depth
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
 * Deep-validate an untrusted policy (id, name, algorithm, rules, conditions).
 *
 * @param input - The candidate policy object (typically parsed JSON or an admin form payload).
 * @returns A {@link IamValidate.IResult} with `valid: false` when any error issue was emitted.
 */
export function iamValidatePolicy(input: unknown): IamValidate.IResult {
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

  if (typeof p.algorithm !== 'string' || !IAM_VALID_ALGORITHMS.has(p.algorithm)) {
    issues.push({
      type: 'error',
      code: 'INVALID_ALGORITHM',
      message: `Invalid algorithm "${String(p.algorithm)}". Must be one of: ${[...IAM_VALID_ALGORITHMS].join(', ')}`,
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
    if (p.rules.length > IAM_POLICY_LIMITS.rulesPerPolicy) {
      issues.push({
        type: 'error',
        code: 'LIMIT_EXCEEDED',
        message: `Policy has ${p.rules.length} rules; limit is ${IAM_POLICY_LIMITS.rulesPerPolicy}`,
        path: 'rules',
      })
    }
    for (const [i, rule] of p.rules.entries()) {
      validateRuleShape(rule, `rules[${i}]`, issues)
    }

    // Check for duplicate rule IDs
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

  return { valid: issues.every((i) => i.type !== 'error'), issues }
}

/**
 * Shape guard for a single Role: `id` non-empty, `permissions` array, optional `inherits: string[]`.
 *
 * @param input - The candidate role object (typically parsed JSON).
 * @returns A {@link IamValidate.IResult} with `valid: false` when any error issue was emitted.
 */
export function iamValidateRole(input: unknown): IamValidate.IResult {
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
export function iamParsePolicyRow<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
>(raw: unknown): IamAccessControl.IPolicy<TAction, TResource, TRole> | null {
  if (!iamValidatePolicy(raw).valid) return null
  return raw as IamAccessControl.IPolicy<TAction, TResource, TRole>
}

/** Parse a single role row. Mirror of {@link iamParsePolicyRow}. */
export function iamParseRoleRow<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(raw: unknown): IamAccessControl.IRole<TAction, TResource, TRole, TScope> | null {
  if (!iamValidateRole(raw).valid) return null
  return raw as IamAccessControl.IRole<TAction, TResource, TRole, TScope>
}
