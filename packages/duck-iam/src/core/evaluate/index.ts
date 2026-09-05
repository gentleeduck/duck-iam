// The raw `evaluatePolicy` / `evaluatePolicyFast` are deliberately NOT
// re-exported here. They carry no `allowFailOpen` gate, and exporting them
// under an `iam*` name put an ungated fail-open evaluation on the package
// root. The gated wrappers below are the public names.
export type { IEvalSignals, IVoteSource } from './evaluate'
export { indexPolicy as iamIndexPolicy, VALID_POLICY_COMBINES } from './evaluate.libs'
export { iamEvaluate, iamEvaluateFast, iamEvaluatePolicy, iamEvaluatePolicyFast } from './evaluate.public'
export type { Evaluate } from './evaluate.types'
