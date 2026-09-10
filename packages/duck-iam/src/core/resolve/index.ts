// SECURITY: `pathCache` and `ALLOWED_ROOTS` stay unexported; both are mutable (`ReadonlySet` erases to `Set`), so a
// consumer could break the paths deny rules read. `clearPathCache()` covers the legitimate need.
export {
  clearPathCache,
  matchesAction,
  matchesResource,
  matchesResourceHierarchical,
  matchesScope,
  PATH_CACHE_MAX,
  resolve,
} from './resolve'
