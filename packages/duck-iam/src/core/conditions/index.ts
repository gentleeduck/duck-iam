// SECURITY: `regexCache` and `ops` stay unexported; they are mutable and could be swapped out from under a deny rule.
// NOTE: exports get the `iam`/`IAM_` prefix because they land on the package root.
export {
  evalConditionGroup as iamEvalConditionGroup,
  evaluateOperator as iamEvaluateOperator,
  matchesUnconditionally as iamMatchesUnconditionally,
  resolveConditionValue as iamResolveConditionValue,
} from './conditions'
export {
  clearRegexCache as iamClearRegexCache,
  detectCatastrophicRegex as iamDetectCatastrophicRegex,
  evalCondition as iamEvalCondition,
  getCachedRegex as iamGetCachedRegex,
  isCondition as iamIsCondition,
  isUserSourcedValue as iamIsUserSourcedValue,
  // The limits the evaluator enforces, for pre-flighting patterns. `./core/validate` keeps its unprefixed exports.
  MAX_BOUNDED_QUANTIFIER as IAM_MAX_BOUNDED_QUANTIFIER,
  MAX_CONDITION_DEPTH as IAM_MAX_CONDITION_DEPTH,
  MAX_REGEX_INPUT_LENGTH as IAM_MAX_REGEX_INPUT_LENGTH,
  MAX_REGEX_LENGTH as IAM_MAX_REGEX_LENGTH,
  MAX_UNBOUNDED_QUANTIFIERS as IAM_MAX_UNBOUNDED_QUANTIFIERS,
  REGEX_CACHE_MAX as IAM_REGEX_CACHE_MAX,
  resolveValue as iamResolveValue,
} from './conditions.libs'
