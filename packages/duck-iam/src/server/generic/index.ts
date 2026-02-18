import type { Engine } from '../../core/engine'
import type { Resource, Environment, PermissionCheck, PermissionMap } from '../../core/types'

/**
 * Server-side permission map generator.
 * Call once per request, pass the map to the client.
 */
export async function generatePermissionMap(engine: Engine, subjectId: string, checks: PermissionCheck[], environment?: Environment): Promise<PermissionMap> {
  return engine.permissions(subjectId, checks, environment)
}

/**
 * Create a typed "can" function bound to a subject and engine.
 * Useful in request handlers where you want terse permission checks.
 *
 * Usage:
 *   const can = createSubjectCan(engine, req.user.id);
 *   if (await can("delete", "post")) { ... }
 */
export function createSubjectCan(engine: Engine, subjectId: string, environment?: Environment) {
  return (action: string, resourceType: string, resourceId?: string) =>
    engine.can(subjectId, action, { type: resourceType, id: resourceId, attributes: {} }, environment)
}

/**
 * Standard environment extractor from common request shapes.
 */
export function extractEnvironment(req: {
  ip?: string
  headers?: Record<string, string | string[] | undefined> | Headers
  method?: string
  url?: string
}): Environment {
  const getHeader = (name: string): string | undefined => {
    if (!req.headers) return undefined
    if (req.headers instanceof Headers) return req.headers.get(name) ?? undefined
    const val = (req.headers as Record<string, string | string[] | undefined>)[name]
    return Array.isArray(val) ? val[0] : val
  }

  return {
    ip: req.ip ?? getHeader('x-forwarded-for') ?? getHeader('x-real-ip'),
    userAgent: getHeader('user-agent'),
    timestamp: Date.now(),
  }
}

/**
 * HTTP method to action mapping.
 */
export const METHOD_ACTION_MAP: Record<string, string> = {
  GET: 'read',
  HEAD: 'read',
  OPTIONS: 'read',
  POST: 'create',
  PUT: 'update',
  PATCH: 'update',
  DELETE: 'delete',
}
