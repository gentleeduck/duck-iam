import type { IamPrimitives, IamRequest } from '../types'

/** Top-level path prefixes accepted by {@link resolve}. */
export const ALLOWED_ROOTS: ReadonlySet<string> = new Set(['subject', 'resource', 'environment'])

/**
 * Property names refused at any segment, so such a path is rejected once at parse time rather than walked per request.
 * SECURITY: prototype-pollution guard; exported so the validator's `isResolvablePath` refuses exactly this set.
 */
export const BLOCKED_SEGMENTS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype'])

/** Cap on path-segment caches (~200 bytes an entry, so ~2 MB worst case); evicts in insertion order (FIFO). */
export const PATH_CACHE_MAX = 10_000

/**
 * Process-wide path-segment cache, used when no per-instance cache is passed.
 * NOTE: multi-tenant deployments should pass per-Engine caches so tenants cannot evict each other.
 */
export const pathCache = new Map<string, string[] | null>()

/** Clears the process-wide path cache, e.g. periodically to bound one tenant's eviction influence. */
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
 * Resolves a dot-path field against an {@link IamRequest.IAccessRequest}.
 * SECURITY: reads own properties only, so nothing on the prototype chain is reachable.
 * @param request - The access request providing root data.
 * @param path - Dot-path starting with an allowed root, or the `action` / `scope` shorthand.
 * @param caches - Optional per-Engine path-segment cache; falls back to the module-global one.
 * @returns The resolved attribute value, or `null` when the path is invalid, missing or off-contract.
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
    // SECURITY: own properties only, so `Object.prototype` members (`toString`, ...) never resolve
    // and `exists` means "the request carries it".
    node = Object.hasOwn(node, seg) ? Reflect.get(node, seg) : undefined
  }

  return isAttributeValue(node) ? node : null
}

function isScalar(value: unknown): value is IamPrimitives.Scalar {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

/**
 * Narrows a resolved node to the {@link resolve} contract; adapters can pass nested objects, `Date`s and functions.
 * SECURITY: anything off-contract resolves to `null`, so no operator gives it a wrong `false` that retires a deny.
 */
function isAttributeValue(value: unknown): value is IamPrimitives.AttributeValue {
  if (isScalar(value)) return true
  if (Array.isArray(value)) return value.every(isScalar)
  if (typeof value !== 'object') return false
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) return false
  return Object.values(value).every(isScalar)
}

/** Whether a request action matches a rule pattern: `*` matches all, `posts:*` matches `posts:read`. */
export function matchesAction(pattern: string, action: string): boolean {
  if (pattern === '*') return true
  if (pattern === action) return true

  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1)
    return action.startsWith(prefix)
  }

  return false
}

/** Whether a resource type matches a pattern. Bare is literal; a `:*` / `.*` suffix matches everything under it. */
export function matchesResource(pattern: string, resourceType: string): boolean {
  if (pattern === '*') return true
  if (pattern === resourceType) return true

  // The separator comes from the pattern, so a dot-pattern only matches dot-style resources and vice versa.
  if (pattern.endsWith(':*') || pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -1) // includes the trailing separator
    return resourceType.startsWith(prefix)
  }

  return false
}

/**
 * Dot-notation resource match: `*` is global, `prefix.*` matches the subtree, anything else is literal.
 * A strict subset of {@link matchesResource}, which the engine uses everywhere; this one ignores `':*'`.
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
 * Whether a request scope matches a rule's pattern: `undefined` / `null` / `'*'` match any scope, else exact match.
 * SECURITY: `''` is an ordinary scope value, never a wildcard.
 */
export function matchesScope(pattern: string | undefined | null, scope: string | undefined | null): boolean {
  // Explicit checks, not truthiness: an empty pattern read as global would grant across every scope.
  if (pattern === undefined || pattern === null || pattern === '*') return true
  if (scope === undefined || scope === null) return false
  return pattern === scope
}
