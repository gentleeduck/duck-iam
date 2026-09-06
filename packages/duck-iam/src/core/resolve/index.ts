// `pathCache` and `ALLOWED_ROOTS` are deliberately not re-exported. `pathCache`
// is the process-wide dot-path segment pool, and handing consumers the mutable
// Map lets any of them seat a bogus segment list under a path a deny rule
// resolves. `ALLOWED_ROOTS` is typed `ReadonlySet` but erases to a live `Set`,
// so `.delete('subject')` makes every `subject.*` path unresolvable and flips
// the deny rules that read one - and `pathCache` memoizes that, so it sticks.
// `clearPathCache()` covers the one legitimate operator need.
export {
  clearPathCache,
  matchesAction,
  matchesResource,
  matchesResourceHierarchical,
  matchesScope,
  PATH_CACHE_MAX,
  resolve,
} from './resolve'
