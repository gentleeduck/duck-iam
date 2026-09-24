import { throwIamError } from '../errors'
import type { AccessControl, IamPrimitives, IamRequest } from '../types'
import { evalCondition, isCondition, MAX_CONDITION_DEPTH, ops, resolveValue } from './conditions.libs'

/**
 * Applies one raw operator to two already-resolved operands, for linters and condition previews.
 * SECURITY: has none of `evalCondition`'s guards (`$`-pattern refusal, operand types); never use it to decide access.
 * @param op - The operator to apply.
 * @param fieldValue - Left-hand side, already resolved from the request.
 * @param condValue - Right-hand side, already resolved.
 * @throws When `op` is not one of `ops`' own keys, so a linter cannot report an inherited name as satisfied.
 */
export function evaluateOperator(
  op: AccessControl.Operator,
  fieldValue: IamPrimitives.AttributeValue,
  condValue: IamPrimitives.AttributeValue,
): boolean {
  if (!Object.hasOwn(ops, op)) {
    throwIamError('IAM_CONDITION_OPERATOR_UNKNOWN', { operator: String(op) })
  }
  return ops[op](fieldValue, condValue)
}

/** Resolves a `$`-reference in a condition value against the request; other values pass through unchanged. */
export function resolveConditionValue(
  req: IamRequest.IAccessRequest,
  value: IamPrimitives.AttributeValue,
): IamPrimitives.AttributeValue {
  return resolveValue(req, value)
}

/** Evaluate a single condition or condition group item, dispatching to the appropriate handler. */
function evalItem(
  req: IamRequest.IAccessRequest,
  item: AccessControl.ICondition | AccessControl.IConditionGroup,
  depth: number,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  return isCondition(item) ? evalCondition(req, item, caches) : evalConditionGroup(req, item, depth, caches)
}

/**
 * Returns a group's items, throwing when the key holds a non-array.
 * SECURITY: throwing makes it Indeterminate; reading a broken `none` as empty would satisfy the group.
 */
function assertItems(
  items: unknown,
  key: 'all' | 'any' | 'none',
): ReadonlyArray<AccessControl.ICondition | AccessControl.IConditionGroup> {
  if (!Array.isArray(items)) {
    throwIamError('IAM_CONDITION_ITEMS_NOT_ARRAY', { key })
  }
  return items
}

/**
 * Evaluates an `all` (AND) / `any` (OR) / `none` (NOR) condition tree against the request.
 * SECURITY: too deep, a non-object, or unknown keys throw `IAM_CONDITION_GROUP_INVALID`; `false` would retire a
 * deny rule.
 * @param req - The access request providing field values.
 * @param group - The condition group to evaluate.
 * @param depth - Current recursion depth (internal, do not set).
 * @param caches - Optional per-Engine regex / path caches; falls back to the module-global ones.
 */
export function evalConditionGroup(
  req: IamRequest.IAccessRequest,
  group: AccessControl.IConditionGroup,
  depth = 0,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (depth >= MAX_CONDITION_DEPTH) {
    throwIamError('IAM_CONDITION_GROUP_INVALID', {
      reason: 'depth',
      detail: `condition nesting exceeds ${MAX_CONDITION_DEPTH}`,
    })
  }

  // SECURITY: `in` throws a bare TypeError on a non-object, so the key tests below cannot report one. Indeterminate.
  if (group === null || typeof group !== 'object') {
    throwIamError('IAM_CONDITION_GROUP_INVALID', {
      reason: 'unknown-keys',
      detail: `condition group is not an object (saw ${typeof group})`,
    })
  }

  if ('all' in group) {
    return assertItems(group.all, 'all').every((item) => evalItem(req, item, depth + 1, caches))
  }

  if ('any' in group) {
    return assertItems(group.any, 'any').some((item) => evalItem(req, item, depth + 1, caches))
  }

  if ('none' in group) {
    return !assertItems(group.none, 'none').some((item) => evalItem(req, item, depth + 1, caches))
  }

  // `{}` means no conditions, which is unconditionally true.
  const keys = Object.keys(group)
  if (keys.length === 0) return true

  // Unknown keys (a typo, a hand-edited row): "no conditions" would grant and `false` would retire a deny, so throw.
  throwIamError('IAM_CONDITION_GROUP_INVALID', {
    reason: 'unknown-keys',
    detail: `condition group has no recognised key (saw ${keys.join(', ')})`,
  })
}

/**
 * Whether {@link evalConditionGroup} returns `true` for this group on any request: `{}`, empty `all`, empty `none`.
 * WARN: an empty `any` is always `false`, not unconditional; key precedence must match `evalConditionGroup`.
 */
export function matchesUnconditionally(group: AccessControl.IConditionGroup | undefined): boolean {
  if (group === null || typeof group !== 'object') return false
  if ('all' in group) return Array.isArray(group.all) && group.all.length === 0
  if ('any' in group) return false
  if ('none' in group) return Array.isArray(group.none) && group.none.length === 0
  return Object.keys(group).length === 0
}
