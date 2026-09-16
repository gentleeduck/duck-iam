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
 * SECURITY: the evaluator is public, so all four entry points enforce the engine's `allowFailOpen` opt-in;
 * `fail-open-optin-parity.test.ts` pins them together. Internal callers import `./evaluate` and skip this.
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
