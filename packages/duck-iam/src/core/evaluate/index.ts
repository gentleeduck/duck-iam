// SECURITY: the raw `evaluatePolicy` / `evaluatePolicyFast` are not re-exported; they carry no `allowFailOpen`
// gate, so the gated wrappers below are the public names.
export type { IEvalSignals, IVoteSource } from './evaluate'
export { indexPolicy as iamIndexPolicy, VALID_POLICY_COMBINES } from './evaluate.libs'
export { iamEvaluate, iamEvaluateFast, iamEvaluatePolicy, iamEvaluatePolicyFast } from './evaluate.public'
export type { Evaluate } from './evaluate.types'
