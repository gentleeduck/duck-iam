import type { IamPrimitives, IamRequest } from '../types'

/** Top-level path prefixes accepted by {@link resolve}. */
export const ALLOWED_ROOTS = new Set(['subject', 'resource', 'environment'])

/** Property names refused at any segment - blocks prototype-pollution lookups. */
const BLOCKED_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * Hard cap for path-segment caches. Each entry is at most ~200 bytes
 * (path string + segment array), so 10k entries ~ 2 MB worst case.
 * Insertion-order eviction (FIFO) when the cap is hit.
 */
export const PATH_CACHE_MAX = 10_000

/**
 * Process-wide default path-segment cache. Used when a caller does not pass
 * a per-instance cache. Multi-tenant deployments should prefer per-Engine
 * caches to prevent cross-tenant eviction.
 */
export const pathCache = new Map<string, string[] | null>()

/**
 * Drop every entry in the process-wide path cache. Intended for multi-tenant
 * operators who flush periodically to bound any single tenant's eviction
 * influence.
 */
export function clearPathCache(): void {
  pathCache.clear()
}

function rememberPath(cache: Map<string, string[] | null>, path: string, value: string[] | null): string[] | null {
  if (cache.size >= PATH_CACHE_MAX) {
    const oldest = cache.keys().next().value
    if (oldest !== undefined) cache.delete(oldest)
  }
  cache.set(path, value)
  return value
}

/**
 * Splits and validates a dot-path, memoizing the result.
 * Returns `null` for paths with an unknown root or a blocked segment.
 */
function getSegments(path: string, cache: Map<string, string[] | null> = pathCache): string[] | null {
  const cached = cache.get(path)
  if (cached !== undefined) return cached

  const segments = path.split('.')

  if (!segments[0] || !ALLOWED_ROOTS.has(segments[0])) return rememberPath(cache, path, null)

  for (const seg of segments) {
    if (BLOCKED_SEGMENTS.has(seg)) return rememberPath(cache, path, null)
  }

  return rememberPath(cache, path, segments)
}

/**
 * Resolve a dot-path field against an {@link IamRequest.IAccessRequest}; blocks `__proto__` / `constructor` / `prototype`.
 *
 * @param request - The access request providing root data.
 * @param path    - Dot-path string starting with an allowed root or shorthand.
 * @param caches  - Optional per-Engine path-segment cache; falls back to the module-global one.
 * @returns The resolved attribute value, or `null` when the path is invalid or missing.
 */
export function resolve(
  request: IamRequest.IAccessRequest,
  path: string,
  caches?: { path?: Map<string, string[] | null> },
): IamPrimitives.AttributeValue {
  if (path === 'action') return request.action
  if (path === 'scope') return request.scope ?? null

  // Per-Engine path cache when supplied, module-global fallback otherwise.
  const segments = getSegments(path, caches?.path)
  if (!segments) return null

  let node: unknown = request

  for (const seg of segments) {
    if (node == null || typeof node !== 'object') return null
    node = Reflect.get(node, seg)
  }

  return node === undefined ? null : (node as IamPrimitives.AttributeValue)
}

/**
 * Tests if an action matches a pattern.
 * Supports wildcards: "*" matches all, "posts:*" matches "posts:read", "posts:write"
 *
 * @param pattern - Action pattern from a rule (may include `'*'` or `'foo:*'`).
 * @param action  - The literal action from the request.
 * @returns `true` when the request action matches the pattern.
 */
export function matchesAction(pattern: string, action: string): boolean {
  if (pattern === '*') return true
  if (pattern === action) return true

  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1)
    return action.startsWith(prefix)
  }

  return false
}

/**
 * Match a resource type against a pattern. Bare = literal; `:*` / `.*` suffixes match recursively under the separator.
 *
 * @param pattern      - Resource pattern from a rule.
 * @param resourceType - The literal resource type from the request.
 * @returns `true` when the request resource type matches the pattern.
 */
export function matchesResource(pattern: string, resourceType: string): boolean {
  if (pattern === '*') return true
  if (pattern === resourceType) return true

  // Recognise both `:*` and `.*` as recursive suffixes. The separator is
  // taken from the pattern, so a dot-pattern only matches dot-style request
  // resources and vice versa.
  if (pattern.endsWith(':*') || pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -1) // includes the trailing separator
    return resourceType.startsWith(prefix)
  }

  return false
}

/**
 * Match a resource type against a dot-notation hierarchical pattern; `*` global, `prefix.*` recursive subtree.
 *
 * @param pattern      - Resource pattern from a rule (dot-notation).
 * @param resourceType - The literal resource type from the request.
 * @returns `true` when the request resource type matches the pattern.
 */
export function matchesResourceHierarchical(pattern: string, resourceType: string): boolean {
  if (pattern === '*') return true
  if (pattern === resourceType) return true

  // Only an explicit `.*` suffix enables recursive prefix match.
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -1) // includes trailing '.'
    return resourceType.startsWith(prefix)
  }

  return false
}

/**
 * Tests if a scope matches a pattern.
 *
 * - undefined/null pattern or "*" matches any scope (global permission)
 * - If request has no scope, only global patterns match
 * - Otherwise exact match
 *
 * @param pattern - Scope pattern from a rule (may be `undefined`, `null`, or `'*'`).
 * @param scope   - The request's scope (may be `undefined` or `null`).
 * @returns `true` when the request scope matches the pattern.
 */
export function matchesScope(pattern: string | undefined | null, scope: string | undefined | null): boolean {
  if (!pattern || pattern === '*') return true
  if (!scope) return false
  return pattern === scope
}
