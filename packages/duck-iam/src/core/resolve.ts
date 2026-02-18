import type { AccessRequest, AttributeValue } from './types'

/**
 * Resolves dot-path field references against an AccessRequest.
 *
 * Supported paths:
 *   subject.id, subject.roles, subject.attributes.*
 *   resource.type, resource.id, resource.attributes.*
 *   environment.*
 *   action (shorthand for the action string)
 *
 * Special tokens:
 *   $subject.id  -> replaced at eval time with subject.id
 */
export function resolve(request: AccessRequest, path: string): AttributeValue {
  if (path === 'action') return request.action

  const segments = path.split('.')
  let node: unknown = request

  for (const seg of segments) {
    if (node == null || typeof node !== 'object') return null
    node = (node as Record<string, unknown>)[seg]
  }

  return node === undefined ? null : (node as AttributeValue)
}

/**
 * Tests if an action matches a pattern.
 * Supports wildcards: "*" matches all, "posts:*" matches "posts:read", "posts:write"
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
 * Tests if a resource type matches a pattern.
 * Supports hierarchical matching: "org:*" matches "org:project", "org:project:doc"
 */
export function matchesResource(pattern: string, resourceType: string): boolean {
  if (pattern === '*') return true
  if (pattern === resourceType) return true

  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1)
    return resourceType.startsWith(prefix)
  }

  // Hierarchical: "org" matches "org:project:doc"
  if (resourceType.startsWith(pattern + ':')) return true

  return false
}
