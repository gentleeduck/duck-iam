import type { Role } from './types'

export interface ValidationIssue {
  readonly type: 'error' | 'warning'
  readonly code: string
  readonly message: string
  readonly roleId?: string
  readonly path?: string
}

export interface ValidationResult {
  readonly valid: boolean
  readonly issues: readonly ValidationIssue[]
}

// ------------------------------------------------------------
// Role validation
// ------------------------------------------------------------

/**
 * Validate role definitions for common configuration mistakes.
 *
 * Checks for:
 * - Duplicate role IDs
 * - Dangling `inherits` references (role inherits from non-existent role)
 * - Circular inheritance chains (detected and reported as warnings since they're handled at runtime)
 * - Roles with no permissions and no inheritance
 */
export function validateRoles(roles: readonly Role[]): ValidationResult {
  const issues: ValidationIssue[] = []
  const roleIds = new Set<string>()

  // Check for duplicate IDs
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

  // Check for dangling inherits references
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

  // Check for circular inheritance
  const rolesMap = new Map(roles.map((r) => [r.id, r]))

  for (const role of roles) {
    if (!role.inherits?.length) continue

    const visited = new Set<string>()
    const stack = [role.id]

    while (stack.length > 0) {
      const current = stack.pop()!
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

  // Check for empty roles (no permissions, no inheritance)
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

  return {
    valid: issues.every((i) => i.type !== 'error'),
    issues,
  }
}

// ------------------------------------------------------------
// Policy validation (runtime validation for dynamic/untrusted policies)
// ------------------------------------------------------------

const VALID_ALGORITHMS = new Set(['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'])

const VALID_EFFECTS = new Set(['allow', 'deny'])

const VALID_OPERATORS = new Set([
  'eq',
  'neq',
  'gt',
  'gte',
  'lt',
  'lte',
  'in',
  'nin',
  'contains',
  'not_contains',
  'starts_with',
  'ends_with',
  'matches',
  'exists',
  'not_exists',
  'subset_of',
  'superset_of',
])

function validateConditionItem(input: unknown, path: string, issues: ValidationIssue[]): void {
  if (typeof input !== 'object' || input === null) {
    issues.push({ type: 'error', code: 'INVALID_CONDITION', message: 'Condition must be an object', path })
    return
  }

  const obj = input as Record<string, unknown>

  if ('field' in obj) {
    // Leaf condition
    if (typeof obj.field !== 'string' || !obj.field) {
      issues.push({
        type: 'error',
        code: 'MISSING_FIELD',
        message: 'Condition must have a non-empty string "field"',
        path: `${path}.field`,
      })
    }
    if (!VALID_OPERATORS.has(obj.operator as string)) {
      issues.push({
        type: 'error',
        code: 'INVALID_OPERATOR',
        message: `Invalid operator "${String(obj.operator)}"`,
        path: `${path}.operator`,
      })
    }
  } else {
    // Group condition
    validateConditionGroup(input, path, issues)
  }
}

function validateConditionGroup(input: unknown, path: string, issues: ValidationIssue[]): void {
  if (typeof input !== 'object' || input === null) {
    issues.push({ type: 'error', code: 'INVALID_CONDITION', message: 'Condition group must be an object', path })
    return
  }

  const obj = input as Record<string, unknown>
  const groupKey = ['all', 'any', 'none'].find((k) => k in obj)

  if (!groupKey) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: 'Condition group must have "all", "any", or "none" key',
      path,
    })
    return
  }

  const items = obj[groupKey]
  if (!Array.isArray(items)) {
    issues.push({
      type: 'error',
      code: 'INVALID_CONDITION',
      message: `"${groupKey}" must be an array`,
      path: `${path}.${groupKey}`,
    })
    return
  }

  for (const [i, item] of items.entries()) {
    validateConditionItem(item, `${path}.${groupKey}[${i}]`, issues)
  }
}

function validateRuleShape(input: unknown, path: string, issues: ValidationIssue[]): void {
  if (typeof input !== 'object' || input === null) {
    issues.push({ type: 'error', code: 'INVALID_RULE', message: 'Rule must be an object', path })
    return
  }

  const rule = input as Record<string, unknown>

  if (typeof rule.id !== 'string' || !rule.id) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a non-empty string "id"',
      path: `${path}.id`,
    })
  }

  if (!VALID_EFFECTS.has(rule.effect as string)) {
    issues.push({
      type: 'error',
      code: 'INVALID_EFFECT',
      message: `Invalid effect "${String(rule.effect)}". Must be "allow" or "deny"`,
      path: `${path}.effect`,
    })
  }

  if (typeof rule.priority !== 'number') {
    issues.push({
      type: 'error',
      code: 'INVALID_TYPE',
      message: 'Rule "priority" must be a number',
      path: `${path}.priority`,
    })
  }

  if (!Array.isArray(rule.actions) || rule.actions.length === 0) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a non-empty "actions" array',
      path: `${path}.actions`,
    })
  } else {
    for (const [i, action] of (rule.actions as unknown[]).entries()) {
      if (typeof action !== 'string') {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Action must be a string',
          path: `${path}.actions[${i}]`,
        })
      }
    }
  }

  if (!Array.isArray(rule.resources) || rule.resources.length === 0) {
    issues.push({
      type: 'error',
      code: 'MISSING_FIELD',
      message: 'Rule must have a non-empty "resources" array',
      path: `${path}.resources`,
    })
  } else {
    for (const [i, resource] of (rule.resources as unknown[]).entries()) {
      if (typeof resource !== 'string') {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: 'Resource must be a string',
          path: `${path}.resources[${i}]`,
        })
      }
    }
  }

  if (rule.conditions !== undefined) {
    validateConditionGroup(rule.conditions, `${path}.conditions`, issues)
  }
}

/**
 * Validate a policy object from an untrusted source (database, API, admin dashboard).
 *
 * Deeply validates the entire policy structure including:
 * - Required fields: id, name, algorithm, rules
 * - Valid combining algorithm
 * - Each rule: id, effect, priority, actions, resources, conditions
 * - Valid operators in conditions
 * - Correct condition group structure (all/any/none with arrays)
 *
 * Use this before feeding dynamic policies to the engine:
 *
 *   const result = validatePolicy(jsonFromDatabase);
 *   if (!result.valid) throw new Error(result.issues.map(i => i.message).join(', '));
 *   engine.admin.savePolicy(jsonFromDatabase as Policy);
 */
export function validatePolicy(input: unknown): ValidationResult {
  const issues: ValidationIssue[] = []

  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    issues.push({ type: 'error', code: 'INVALID_TYPE', message: 'Policy must be a non-null object', path: '' })
    return { valid: false, issues }
  }

  const p = input as Record<string, unknown>

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

  if (!VALID_ALGORITHMS.has(p.algorithm as string)) {
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
    for (const [i, rule] of (p.rules as unknown[]).entries()) {
      validateRuleShape(rule, `rules[${i}]`, issues)
    }

    // Check for duplicate rule IDs
    const ruleIds = new Set<string>()
    for (const rule of p.rules as Array<Record<string, unknown>>) {
      if (typeof rule?.id === 'string') {
        if (ruleIds.has(rule.id)) {
          issues.push({
            type: 'warning',
            code: 'DUPLICATE_RULE_ID',
            message: `Duplicate rule ID "${rule.id}"`,
            path: 'rules',
          })
        }
        ruleIds.add(rule.id)
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
      const targets = p.targets as Record<string, unknown>
      for (const key of ['actions', 'resources', 'roles'] as const) {
        if (targets[key] !== undefined && !Array.isArray(targets[key])) {
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
