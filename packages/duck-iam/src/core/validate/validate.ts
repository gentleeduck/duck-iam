import { IAM_RBAC_CONDITION_DEPTH, MAX_INHERITANCE_DEPTH } from '../rbac'
import { matchesAction, matchesResource } from '../resolve'
import type { AccessControl } from '../types'
import {
  checkKnownKeys,
  hasControlChar,
  POLICY_KEYS,
  POLICY_LIMITS,
  TARGET_KEYS,
  VALID_ALGORITHMS,
  validateConditionGroup,
  validateRuleShape,
} from './validate.libs'
import type { IamValidate } from './validate.types'

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((item) => typeof item === 'string')
}
/**
 * Validate role defs: shape, duplicate ids, dangling/circular/too-deep inherits, empty roles, undeclared targets.
 *
 * @param roles    - Untrusted role definitions; a malformed entry is reported, never thrown on.
 * @param declared - Config vocabulary to check grants against; omit it to skip that pass.
 * @returns A {@link IamValidate.IResult} listing any issues found.
 */
export function validateRoles(
  roles: readonly AccessControl.IRole[],
  declared?: IamValidate.IDeclaredSurface,
): IamValidate.IResult {
  const issues: IamValidate.IIssue[] = []
  const roleIds = new Set<string>()

  // Input is untrusted (adapter row, config entry, form body), so a malformed entry is an issue, never a `TypeError`.
  const wellFormed: AccessControl.IRole[] = []
  for (const [index, role] of roles.entries()) {
    // Check everything the passes below dereference; a string `inherits` would iterate characters instead of throwing.
    const why = !isPlainObject(role)
      ? 'is not an object'
      : typeof role.id !== 'string' || role.id === ''
        ? 'has no non-empty string "id"'
        : !Array.isArray(role.permissions)
          ? 'has no "permissions" array'
          : role.inherits !== undefined && !isStringArray(role.inherits)
            ? 'has an "inherits" that is not an array of strings'
            : undefined
    if (why !== undefined) {
      issues.push({
        type: 'error',
        // WARN: reuse `INVALID_TYPE`; consumers switch on the published `ValidationCode` union.
        code: 'INVALID_TYPE',
        message: `Role at index ${index} ${why}`,
        ...(isPlainObject(role) && typeof role.id === 'string' ? { roleId: role.id } : {}),
      })
      continue
    }
    wellFormed.push(role as unknown as AccessControl.IRole)
  }

  for (const role of wellFormed) {
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

  for (const role of wellFormed) {
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

  // Cycles are runtime-safe (cut by `resolveEffectiveRoles`' shallowest-depth memo), so they are warnings.
  const rolesMap = new Map(wellFormed.map((r) => [r.id, r]))

  for (const role of wellFormed) {
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

  for (const role of wellFormed) {
    if (role.permissions.length === 0 && (!role.inherits || role.inherits.length === 0)) {
      issues.push({
        type: 'warning',
        code: 'EMPTY_ROLE',
        message: `Role "${role.id}" has no permissions and no inheritance`,
        roleId: role.id,
      })
    }
  }

  // Chains deeper than MAX_INHERITANCE_DEPTH truncate at runtime, so this is an error caught before deploy.
  for (const role of wellFormed) {
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

  // `createIam` constrains `engine.check` to the declared unions, so an undeclared grant reads as granted but never
  // matches. `createIam(...).validateRoles` passes `declared`; the bare export skips this pass.
  if (declared !== undefined) {
    for (const role of wellFormed) {
      for (const [i, perm] of role.permissions.entries()) {
        const path = `permissions[${i}]`
        undeclared(issues, declared.actions, perm.action, 'action', role.id, path)
        undeclared(issues, declared.resources, perm.resource, 'resource', role.id, path)
        undeclared(issues, declared.scopes, perm.scope, 'scope', role.id, path)
      }
      undeclared(issues, declared.scopes, role.scope, 'scope', role.id, 'scope')
    }
  }

  return {
    valid: issues.every((i) => i.type !== 'error'),
    issues,
  }
}

/**
 * Push an `UNREACHABLE_TARGET` error when `value` is outside the declared vocabulary.
 * Never reported: an empty axis, a `'*'` grant, or an absent value (an unscoped permission is global).
 */
function undeclared(
  issues: IamValidate.IIssue[],
  allowed: readonly string[] | undefined,
  value: string | undefined,
  axis: 'action' | 'resource' | 'scope',
  roleId: string,
  path: string,
): void {
  if (allowed === undefined || allowed.length === 0) return
  if (value === undefined || value === '*') return
  if (allowed.includes(value)) return
  issues.push({
    type: 'error',
    code: 'UNREACHABLE_TARGET',
    message: `Role "${roleId}" grants ${axis} "${value}", which the config never declared; no request can reach it. Declared ${axis}s: ${allowed.map((a) => `"${a}"`).join(', ')}.`,
    path,
    roleId,
  })
}

/** Longest `inherits` path from `roleId`; cycles cut by `seen`, depth capped at `MAX_INHERITANCE_DEPTH + 1`. */
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
 * Flag target pairs no allow rule covers, since a matched target with no matching rule folds to `deny`.
 * Only runs once the policy has an allow rule, so a purely restrictive policy is left alone.
 */
function checkTargetIsReachable(p: Record<string, unknown>, issues: IamValidate.IIssue[]): void {
  const targets = p.targets
  if (!isPlainObject(targets)) return

  // Only well-formed rules count; a malformed one already has its `INVALID_RULE` and must not throw here.
  const allows = (Array.isArray(p.rules) ? p.rules : []).filter(
    (rule): rule is Record<string, unknown> => isPlainObject(rule) && rule.effect === 'allow',
  )
  if (allows.length === 0) return

  // An absent, empty, or non-string list covers everything, so an already-reported row adds no second issue.
  const covers = (list: unknown, value: string) =>
    !isStringArray(list) || list.length === 0 || list.includes('*') || list.includes(value)

  // An omitted dimension is left to the rules, not expanded to `'*'`. A non-array list already errored as
  // `INVALID_TYPE`; treat it as unconstrained, or the string `'read'` yields one issue per character.
  const targetList = (key: 'actions' | 'resources'): string[] | null => {
    const value = Reflect.get(targets, key)
    return isStringArray(value) && value.length > 0 ? value : null
  }
  const actions = targetList('actions')
  const resources = targetList('resources')
  if (!actions && !resources) return

  // PERF: same cartesian budget as rules, so an oversized target can't push one issue per pair.
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
        // NOTE: an error, so `PolicyBuilder.build()` throws where the policy is written; a denial looks like success.
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
 * Flag a rule pattern or target entry outside the config's vocabulary, which no request can reach.
 * Uses the engine's own matchers, so a prefix pattern is cleared on exactly the values it would match at runtime.
 */
function checkDeclaredVocabulary(
  p: Record<string, unknown>,
  declared: IamValidate.IDeclaredSurface,
  issues: IamValidate.IIssue[],
): void {
  const unreachable = (value: string, axis: 'action' | 'resource' | 'role', allowed: readonly string[], path: string) =>
    issues.push({
      type: 'error',
      code: 'UNREACHABLE_TARGET',
      message: `${axis === 'role' ? 'Targets' : 'Rule'} ${axis} "${value}" is outside the config vocabulary; no request can reach it. Declared ${axis}s: ${allowed.map((a) => `"${a}"`).join(', ')}.`,
      path,
    })

  const check = (
    list: unknown,
    axis: 'action' | 'resource',
    allowed: readonly string[] | undefined,
    path: string,
  ): void => {
    if (allowed === undefined || allowed.length === 0 || !isStringArray(list)) return
    const match = axis === 'action' ? matchesAction : matchesResource
    for (const [i, pattern] of list.entries()) {
      if (allowed.some((value) => match(pattern, value))) continue
      unreachable(pattern, axis, allowed, `${path}.${axis}s[${i}]`)
    }
  }

  for (const [i, rule] of (Array.isArray(p.rules) ? p.rules : []).entries()) {
    if (!isPlainObject(rule)) continue
    check(rule.actions, 'action', declared.actions, `rules[${i}]`)
    check(rule.resources, 'resource', declared.resources, `rules[${i}]`)
  }

  const targets = p.targets
  if (!isPlainObject(targets)) return
  check(targets.actions, 'action', declared.actions, 'targets')
  check(targets.resources, 'resource', declared.resources, 'targets')
  // Roles are matched by equality, never by pattern: `policyApplies` tests `targets.roles.includes`.
  const roles = declared.roles
  if (roles === undefined || roles.length === 0 || !isStringArray(targets.roles)) return
  for (const [i, role] of targets.roles.entries()) {
    if (roles.includes(role)) continue
    unreachable(role, 'role', roles, `targets.roles[${i}]`)
  }
}

/**
 * Deep-validate an untrusted policy (id, name, algorithm, rules, conditions).
 *
 * @param input - The candidate policy object (typically parsed JSON or an admin form payload).
 * @returns A {@link IamValidate.IResult} with `valid: false` when any error issue was emitted.
 */
export function validatePolicy(input: unknown, declared?: IamValidate.IDeclaredSurface): IamValidate.IResult {
  const issues: IamValidate.IIssue[] = []

  if (!isPlainObject(input)) {
    issues.push({ type: 'error', code: 'INVALID_TYPE', message: 'Policy must be a non-null object', path: '' })
    return { valid: false, issues }
  }

  const p = input
  checkKnownKeys(p, POLICY_KEYS, '', issues)

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
      checkKnownKeys(targets, TARGET_KEYS, 'targets', issues)
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

  // `createIam` constrains `engine.check` to the declared unions, so an undeclared action or resource reads as a
  // rule and matches nothing. `createIam(...).validatePolicy` passes `declared`; the bare export skips this pass.
  if (declared !== undefined) checkDeclaredVocabulary(p, declared, issues)

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
  } else if (hasControlChar(r.id)) {
    // SECURITY: refused as the JSON Schema does. NUL is redis's assignment member separator, so `assignRole` would
    // throw on a saved role, and the character is invisible in any UI.
    issues.push({
      type: 'error',
      code: 'INVALID_TYPE',
      message: `Role "id" must not contain control characters`,
      path: 'id',
    })
  }

  // Same contract as `permissions[i].scope` below: `''` would be an unreachable real scope, so omit the field instead.
  if (r.scope !== undefined && (typeof r.scope !== 'string' || r.scope === '')) {
    issues.push({
      type: 'error',
      code: 'INVALID_TYPE',
      message: '"scope" must be a non-empty string if provided (omit it for an unscoped role)',
      path: 'scope',
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
    // Check each entry, so `[null]` or `[{}]` can't reach key building as `undefined:undefined`.
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
        const value = perm[field]
        if (typeof value !== 'string' || value === '') {
          issues.push({
            type: 'error',
            code: 'MISSING_FIELD',
            message: `"permissions[${i}].${field}" must be a non-empty string`,
            path: `permissions[${i}].${field}`,
          })
        } else if (hasControlChar(value)) {
          // SECURITY: `rolesToPolicy` turns these into rule `actions` / `resources`, so they get the same refusal.
          issues.push({
            type: 'error',
            code: 'INVALID_TYPE',
            message: `"permissions[${i}].${field}" must not contain control characters`,
            path: `permissions[${i}].${field}`,
          })
        }
      }
      // SECURITY: `''` is refused, not normalised: redis spells "no scope" as `''`. Omit the field for global.
      if (perm.scope !== undefined && (typeof perm.scope !== 'string' || perm.scope === '')) {
        issues.push({
          type: 'error',
          code: 'INVALID_TYPE',
          message: `"permissions[${i}].scope" must be a non-empty string if provided (omit it for a global permission)`,
          path: `permissions[${i}].scope`,
        })
      }
      if (perm.conditions !== undefined) {
        if (!isPlainObject(perm.conditions)) {
          issues.push({
            type: 'error',
            code: 'INVALID_TYPE',
            message: `"permissions[${i}].conditions" must be an object if provided`,
            path: `permissions[${i}].conditions`,
          })
        } else {
          // SECURITY: an unchecked unknown operator throws at evaluation, where the two engines catch it differently.
          // Start at `IAM_RBAC_CONDITION_DEPTH`, where `rolesToPolicy` nests the group; `0` accepts one level too deep.
          validateConditionGroup(perm.conditions, `permissions[${i}].conditions`, issues, IAM_RBAC_CONDITION_DEPTH)
        }
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
 * NOTE: the unions are TS-only and trusted at the adapter boundary, not checked at runtime.
 *
 * @template TAction   - Action string union.
 * @template TResource - Resource string union.
 * @template TRole     - Role string union.
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
