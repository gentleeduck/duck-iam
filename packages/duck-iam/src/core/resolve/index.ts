// `pathCache` is deliberately not re-exported: it is the process-wide dot-path
// segment pool, and handing consumers the mutable Map lets any of them seat a
// bogus segment list under a path a deny rule resolves. `clearPathCache()`
// covers the one legitimate operator need. Mirrors `conditions`' regexCache.
export {
  ALLOWED_ROOTS,
  clearPathCache,
  matchesAction,
  matchesResource,
  matchesResourceHierarchical,
  matchesScope,
  PATH_CACHE_MAX,
  resolve,
} from './resolve'
