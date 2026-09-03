import type { AccessControl, IamRequest } from '../types'
import { evaluate, evaluateFast, type IEvalSignals } from './evaluate'

type Caches = { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> }

/**
 * `IamEngine` refuses `defaultEffect: 'allow'` without `allowFailOpen: true`,
 * but the evaluator is public too, so that gate was one import away from being
 * bypassed - `evaluate(policies, req, 'allow')` off the package root reached a
 * fail-open evaluation with no opt-in and no warning. These wrappers are the
 * only route to the evaluator from outside the package (nothing below
 * `./core` is in the exports map), so requiring the same confirmation here
 * closes it without putting a per-request check on the hot path.
 */
function assertFailOpenOptIn(defaultEffect: AccessControl.Effect, allowFailOpen: boolean): void {
  if (defaultEffect === 'allow' && !allowFailOpen) {
    throw new Error(
      "[@gentleduck/iam:evaluate] defaultEffect 'allow' is a fail-open footgun. Pass `allowFailOpen: true` to confirm intent.",
    )
  }
}

/** {@link evaluate} with the `defaultEffect: 'allow'` opt-in the engine also requires. */
export function iamEvaluate(
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  combine: AccessControl.PolicyCombine = 'and',
  onPolicyError?: AccessControl.PolicyErrorHandler,
  signals?: IEvalSignals,
  caches?: Caches,
  allowFailOpen = false,
): AccessControl.IDecision {
  assertFailOpenOptIn(defaultEffect, allowFailOpen)
  return evaluate(policies, request, defaultEffect, combine, onPolicyError, signals, caches)
}

/** {@link evaluateFast} with the `defaultEffect: 'allow'` opt-in the engine also requires. */
export function iamEvaluateFast(
  policies: AccessControl.IPolicy[],
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  combine: AccessControl.PolicyCombine = 'and',
  onPolicyError?: AccessControl.PolicyErrorHandler,
  signals?: IEvalSignals,
  caches?: Caches,
  allowFailOpen = false,
): boolean {
  assertFailOpenOptIn(defaultEffect, allowFailOpen)
  return evaluateFast(policies, request, defaultEffect, combine, onPolicyError, signals, caches)
}
