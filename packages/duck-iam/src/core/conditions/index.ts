export { evalConditionGroup, evaluateOperator, resolveConditionValue } from './conditions'
// `regexCache` is deliberately not re-exported: it is the process-wide compile
// pool, and handing consumers the mutable Map lets any of them seat a
// permissive RegExp under a pattern a deny rule relies on. `clearRegexCache()`
// covers the one legitimate operator need.
export {
  clearRegexCache,
  detectCatastrophicRegex,
  evalCondition,
  getCachedRegex,
  isCondition,
  isUserSourcedValue,
  MAX_CONDITION_DEPTH,
  MAX_REGEX_LENGTH,
  ops,
  REGEX_CACHE_MAX,
  resolveValue,
} from './conditions.libs'
