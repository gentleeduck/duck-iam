import type { AccessControl, IamRequest } from '../types'
import {
  evaluate,
  evaluateFast,
  evaluatePolicy,
  evaluatePolicyFast,
  type IEvalSignals,
  type IVoteSource,
} from './evaluate'

type Caches = { regex?: Map<string, RegExp>; path?: Map<string, string[] | null> }

/**
 * `IamEngine` refuses `defaultEffect: 'allow'` without `allowFailOpen: true`,
 * but the evaluator is public too, so that gate was one import away from being
 * bypassed - `evaluate(policies, req, 'allow')` off the package root reached a
 * fail-open evaluation with no opt-in and no warning.
 *
 * The first version of this file gated the two multi-policy entries and
 * asserted it had "the only route to the evaluator". It did not: the barrel
 * re-exported the raw single-policy `evaluatePolicy` / `evaluatePolicyFast`
 * straight from `./evaluate`, so `iamEvaluatePolicy(policy, req, 'allow')` off
 * the package root still answered `allowed: true` with no opt-in. The gate now
 * covers all four, and `fail-open-optin-parity.test.ts` pins them together -
 * a half-gated boundary is what made the claim false the first time.
 *
 * Internal callers keep importing from `./evaluate` directly, so this stays off
 * the per-request hot path.
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

/** {@link evaluatePolicy} with the `defaultEffect: 'allow'` opt-in the engine also requires. */
export function iamEvaluatePolicy(
  policy: AccessControl.IPolicy,
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  caches?: Caches,
  onRuleError?: AccessControl.PolicyErrorHandler,
  allowFailOpen = false,
): AccessControl.IDecision {
  assertFailOpenOptIn(defaultEffect, allowFailOpen)
  return evaluatePolicy(policy, request, defaultEffect, caches, onRuleError)
}

/** {@link evaluatePolicyFast} with the `defaultEffect: 'allow'` opt-in the engine also requires. */
export function iamEvaluatePolicyFast(
  policy: AccessControl.IPolicy,
  request: IamRequest.IAccessRequest,
  defaultEffect: AccessControl.Effect = 'deny',
  caches?: Caches,
  voteSource?: IVoteSource,
  onRuleError?: AccessControl.PolicyErrorHandler,
  allowFailOpen = false,
): boolean | null {
  assertFailOpenOptIn(defaultEffect, allowFailOpen)
  return evaluatePolicyFast(policy, request, defaultEffect, caches, voteSource, onRuleError)
}
