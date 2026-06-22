import type { IamAccessControl, IamPrimitives, IamRequest } from '../types'
import { iamEvalCondition, iamIsCondition, IAM_MAX_CONDITION_DEPTH, iamOps, iamResolveValue } from './conditions.libs'

/**
 * IamEvaluate a single operator. Exposed for explain/trace functionality.
 *
 * @param op         - The operator to apply.
 * @param fieldValue - Left-hand side resolved from the request.
 * @param condValue  - Right-hand side from the condition.
 * @returns `true` when the operator predicate holds.
 */
export function iamEvaluateOperator(
  op: IamAccessControl.Operator,
  fieldValue: IamPrimitives.AttributeValue,
  condValue: IamPrimitives.AttributeValue,
): boolean {
  return iamOps[op](fieldValue, condValue)
}

/**
 * Resolve $-variable references in condition values against a request.
 *
 * @param req   - The access request providing resolution roots.
 * @param value - Raw condition value (possibly `$`-prefixed reference).
 * @returns The resolved value, or `value` unchanged when no resolution applies.
 */
export function iamResolveConditionValue(
  req: IamRequest.IAccessRequest,
  value: IamPrimitives.AttributeValue,
): IamPrimitives.AttributeValue {
  return iamResolveValue(req, value)
}

/** IamEvaluate a single condition or condition group item, dispatching to the appropriate handler. */
function evalItem(
  req: IamRequest.IAccessRequest,
  item: IamAccessControl.ICondition | IamAccessControl.IConditionGroup,
  depth: number,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  return iamIsCondition(item) ? iamEvalCondition(req, item, caches) : iamEvalConditionGroup(req, item, depth, caches)
}

/**
 * Evaluates a condition group tree against an access request.
 *
 * Handles `all` (AND), `any` (OR), and `none` (NOT/NOR) groups recursively.
 * Fails closed (returns `false`) when nesting exceeds `IAM_MAX_CONDITION_DEPTH`.
 *
 * @param req   - The access request providing field values
 * @param group - The condition group to evaluate
 * @param depth - Current recursion depth (internal, do not set)
 * @returns Whether the condition group is satisfied
 */
export function iamEvalConditionGroup(
  req: IamRequest.IAccessRequest,
  group: IamAccessControl.IConditionGroup,
  depth = 0,
  caches?: { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> },
): boolean {
  if (depth >= IAM_MAX_CONDITION_DEPTH) {
    return false // Deny when nesting is too deep -- fail closed
  }

  if ('all' in group) {
    return group.all.every((item) => evalItem(req, item, depth + 1, caches))
  }

  if ('any' in group) {
    return group.any.some((item) => evalItem(req, item, depth + 1, caches))
  }

  if ('none' in group) {
    return !group.none.some((item) => evalItem(req, item, depth + 1, caches))
  }

  // Empty object {} = no conditions = unconditionally true
  return true
}
