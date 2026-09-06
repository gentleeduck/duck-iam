// `regexCache` and `ops` are deliberately not re-exported. `regexCache` is the
// process-wide compile pool, and handing consumers the mutable Map lets any of
// them seat a permissive RegExp under a pattern a deny rule relies on. `ops` is
// worse: it is the operator table itself, so `ops.eq = () => false` retires
// every `eq` deny rule in both evaluation modes. Neither is frozen at runtime,
// so withholding them from the barrel is the only thing keeping them internal.
// `iamClearRegexCache()` covers the one legitimate operator need.
//
// Everything below is renamed on the way out. `export * from './conditions'` in
// `core/index.ts` puts these on the package root, where `evalCondition`,
// `resolveValue` and `isCondition` are names a consumer's own code plausibly
// uses; the `iam`/`IAM_` prefix is the house convention for exactly that
// reason. Internal callers import the implementation modules directly and keep
// the short names.
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
  IamRegexInputTooLargeError,
  isCondition as iamIsCondition,
  isUserSourcedValue as iamIsUserSourcedValue,
  // All six regex/condition limits, not the four that happened to be needed
  // first. `MAX_BOUNDED_QUANTIFIER` and `MAX_UNBOUNDED_QUANTIFIERS` were
  // reachable only through `./core/validate` - a separate opt-in chunk - and
  // unprefixed there, so a consumer pre-flighting a pattern against the same
  // thresholds the evaluator enforces had to import from two entrypoints under
  // two naming conventions to collect one set of numbers. `./core/validate`
  // keeps its own unprefixed exports; these are the root-barrel names.
  MAX_BOUNDED_QUANTIFIER as IAM_MAX_BOUNDED_QUANTIFIER,
  MAX_CONDITION_DEPTH as IAM_MAX_CONDITION_DEPTH,
  MAX_REGEX_INPUT_LENGTH as IAM_MAX_REGEX_INPUT_LENGTH,
  MAX_REGEX_LENGTH as IAM_MAX_REGEX_LENGTH,
  MAX_UNBOUNDED_QUANTIFIERS as IAM_MAX_UNBOUNDED_QUANTIFIERS,
  REGEX_CACHE_MAX as IAM_REGEX_CACHE_MAX,
  resolveValue as iamResolveValue,
} from './conditions.libs'
