import type { IamPrimitives, IamRequest } from '../types'

/** Top-level path prefixes accepted by {@link resolve}. */
export const ALLOWED_ROOTS: ReadonlySet<string> = new Set(['subject', 'resource', 'environment'])

/**
 * Property names refused at any segment. The own-property walk in {@link resolve}
 * already makes these unreachable; the denylist stays so the path is rejected
 * once, at parse time, and memoized as invalid rather than walked per request.
 */
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
 * Resolve a dot-path field against an {@link IamRequest.IAccessRequest}. Reads
 * own properties only, so nothing on the prototype chain - including
 * `__proto__` / `constructor` / `prototype` - is reachable.
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
    // Own properties only. `Reflect.get` resolves through the prototype chain,
    // so every `Object.prototype` member - `toString`, `valueOf`,
    // `hasOwnProperty`, `__defineGetter__`, … - resolved to a function on any
    // object, and an `exists`-gated allow fired against a subject with no
    // attributes at all. `exists` asks whether the request *carries* the
    // attribute, which is an own-property question.
    node = Object.hasOwn(node, seg) ? Reflect.get(node, seg) : undefined
  }

  return isAttributeValue(node) ? node : null
}

function isScalar(value: unknown): value is IamPrimitives.Scalar {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

/**
 * Narrows a resolved node to the type {@link resolve} promises.
 *
 * Adapters deserialize JSON and hand the result straight through, so deeply
 * nested objects, `Date`s and - from a `getSubjectAttributes` that returns a
 * live object - functions genuinely reach here. Asserting the type instead of
 * establishing it left every operator's own `typeof` guard as the only thing
 * standing between a non-conforming value and a wrong comparison, and a `false`
 * from a deny rule's condition is a silent grant. Anything outside the contract
 * resolves to `null`, which is NotApplicable rather than a guess.
 */
function isAttributeValue(value: unknown): value is IamPrimitives.AttributeValue {
  if (isScalar(value)) return true
  if (Array.isArray(value)) return value.every(isScalar)
  if (typeof value !== 'object') return false
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) return false
  return Object.values(value).every(isScalar)
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
 * - Otherwise exact match; `''` is an ordinary scope value, never a wildcard
 *
 * @param pattern - Scope pattern from a rule (may be `undefined`, `null`, or `'*'`).
 * @param scope   - The request's scope (may be `undefined` or `null`).
 * @returns `true` when the request scope matches the pattern.
 */
export function matchesScope(pattern: string | undefined | null, scope: string | undefined | null): boolean {
  // Explicit checks, not truthiness: `''` is a scope value, not a missing one.
  // Reading an empty pattern as "global" made a row with `scope: ''` grant
  // across every scope, which is the opposite of what it looks like.
  if (pattern === undefined || pattern === null || pattern === '*') return true
  if (scope === undefined || scope === null) return false
  return pattern === scope
}
