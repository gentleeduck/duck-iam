import type { AccessControl, IamPrimitives, IamRequest } from '../types'
import { evalCondition, isCondition, MAX_CONDITION_DEPTH, ops, resolveValue } from './conditions.libs'

/**
 * Evaluate a single operator. Exposed for explain/trace functionality.
 *
 * @param op         - The operator to apply.
 * @param fieldValue - Left-hand side resolved from the request.
 * @param condValue  - Right-hand side from the condition.
 * @returns `true` when the operator predicate holds.
 */
export function evaluateOperator(
  op: AccessControl.Operator,
  fieldValue: IamPrimitives.AttributeValue,
  condValue: IamPrimitives.AttributeValue,
): boolean {
  return ops[op](fieldValue, condValue)
}

/**
 * Resolve $-variable references in condition values against a request.
 *
 * @param req   - The access request providing resolution roots.
 * @param value - Raw condition value (possibly `$`-prefixed reference).
 * @returns The resolved value, or `value` unchanged when no resolution applies.
 */
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
 * A group key that is present but not an array is malformed. Throwing makes it
 * indeterminate: reporting it and failing closed beats reading a broken `none`
 * as an empty list, which would satisfy the group unconditionally.
 */
function assertItems(
  items: unknown,
  key: 'all' | 'any' | 'none',
): ReadonlyArray<AccessControl.ICondition | AccessControl.IConditionGroup> {
  if (!Array.isArray(items)) {
    throw new Error(`[@gentleduck/iam:conditions] condition group "${key}" must be an array`)
  }
  return items
}

/**
 * Evaluates a condition group tree against an access request.
 *
 * Handles `all` (AND), `any` (OR), and `none` (NOT/NOR) groups recursively.
 * Fails closed (returns `false`) when nesting exceeds `MAX_CONDITION_DEPTH`.
 *
 * @param req   - The access request providing field values
 * @param group - The condition group to evaluate
 * @param depth - Current recursion depth (internal, do not set)
 * @param caches - Optional per-Engine regex / path caches; falls back to the module-global ones.
 * @returns Whether the condition group is satisfied
 */
export function evalConditionGroup(
  req: IamRequest.IAccessRequest,
  group: AccessControl.IConditionGroup,
  depth = 0,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (depth >= MAX_CONDITION_DEPTH) {
    return false // Deny when nesting is too deep -- fail closed
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

  // `{}` means no conditions, which is unconditionally true. Anything else that
  // reached here has keys we do not recognise (a typo'd `all`, a row from a
  // hand-edited store). Reading that as "no conditions" turns a conditional
  // allow into an unconditional one, so it is false instead.
  return group !== null && typeof group === 'object' && Object.keys(group).length === 0
}
