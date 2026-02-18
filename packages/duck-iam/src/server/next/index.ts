/**
 * Next.js App Router server-side integration.
 *
 * Covers:
 *   - API route wrappers (Route Handlers)
 *   - Server Component helpers
 *   - Next.js Middleware integration
 *   - Permission map generation for client hydration
 */

import type { Engine } from '../../core/engine'
import type { Resource, Environment, PermissionCheck, PermissionMap } from '../../core/types'
import { METHOD_ACTION_MAP } from '../generic'

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// API Route Handler wrapper
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

type RouteContext = { params: Promise<Record<string, string>> | Record<string, string> }
type RouteHandler = (req: Request, ctx: RouteContext) => Promise<Response>

export interface WithAccessOptions {
  getUserId?: (req: Request) => string | null | Promise<string | null>
  getEnvironment?: (req: Request) => Environment
}

/**
 * Wrap a Next.js App Router route handler with access control.
 *
 *   // app/api/posts/[id]/route.ts
 *   import { withAccess } from "access-engine/server/next";
 *
 *   async function handler(req: Request, ctx) {
 *     // Only runs if authorized
 *     return Response.json({ ok: true });
 *   }
 *
 *   export const DELETE = withAccess(engine, "delete", "post", handler);
 *   export const PATCH  = withAccess(engine, "update", "post", handler);
 */
export function withAccess(engine: Engine, action: string, resourceType: string, handler: RouteHandler, opts: WithAccessOptions = {}): RouteHandler {
  const {
    getUserId = (req) => req.headers.get('x-user-id'),
    getEnvironment = (req) => ({
      ip: req.headers.get('x-forwarded-for'),
      userAgent: req.headers.get('user-agent'),
      timestamp: Date.now(),
    }),
  } = opts

  return async (req, ctx) => {
    const userId = await getUserId(req)
    if (!userId) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const params = ctx.params instanceof Promise ? await ctx.params : ctx.params
    const resourceId = params?.id

    const allowed = await engine.can(userId, action, { type: resourceType, id: resourceId, attributes: {} }, getEnvironment(req))

    if (!allowed) {
      return Response.json({ error: 'Forbidden' }, { status: 403 })
    }

    return handler(req, ctx)
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Server Component helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Check a single permission in a Server Component or server action.
 *
 *   export default async function Page() {
 *     const canEdit = await checkAccess(engine, userId, "update", "post");
 *     return canEdit ? <Editor /> : <Viewer />;
 *   }
 */
export async function checkAccess(engine: Engine, subjectId: string, action: string, resourceType: string, resourceId?: string): Promise<boolean> {
  return engine.can(subjectId, action, {
    type: resourceType,
    id: resourceId,
    attributes: {},
  })
}

/**
 * Generate a PermissionMap in a Server Component or layout.
 * Pass this to the AccessProvider on the client side.
 *
 *   // app/layout.tsx
 *   export default async function Layout({ children }) {
 *     const perms = await getPermissions(engine, userId, [
 *       { action: "create", resource: "post" },
 *       { action: "manage", resource: "team" },
 *     ]);
 *     return <AccessProvider permissions={perms}>{children}</AccessProvider>;
 *   }
 */
export async function getPermissions(engine: Engine, subjectId: string, checks: PermissionCheck[]): Promise<PermissionMap> {
  return engine.permissions(subjectId, checks)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Next.js Middleware integration
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export interface NextMiddlewareOptions {
  /** Map URL patterns to required permissions */
  rules: Array<{
    /** Regex or glob pattern for the path */
    pattern: string | RegExp
    /** Required action. If not set, inferred from HTTP method. */
    action?: string
    /** Resource type for this route */
    resource: string
  }>
  getUserId: (req: Request) => string | null | Promise<string | null>
}

/**
 * Create a matcher function for Next.js middleware.
 * Use in middleware.ts to protect routes at the edge.
 *
 *   // middleware.ts
 *   import { createNextMiddleware } from "access-engine/server/next";
 *
 *   const checkAccess = createNextMiddleware(engine, {
 *     getUserId: (req) => getSession(req)?.userId,
 *     rules: [
 *       { pattern: /^\/admin/, resource: "admin", action: "access" },
 *       { pattern: /^\/api\/posts/, resource: "post" },
 *     ],
 *   });
 *
 *   export async function middleware(req: NextRequest) {
 *     return checkAccess(req);
 *   }
 */
export function createNextMiddleware(engine: Engine, opts: NextMiddlewareOptions) {
  return async (req: Request): Promise<Response | null> => {
    const url = new URL(req.url)
    const path = url.pathname

    const matchedRule = opts.rules.find((r) => {
      if (typeof r.pattern === 'string') {
        return path.startsWith(r.pattern)
      }
      return r.pattern.test(path)
    })

    if (!matchedRule) return null // No rule matches, allow through

    const userId = await opts.getUserId(req)
    if (!userId) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const action = matchedRule.action ?? METHOD_ACTION_MAP[req.method] ?? 'read'

    const allowed = await engine.can(userId, action, {
      type: matchedRule.resource,
      attributes: {},
    })

    if (!allowed) {
      return Response.json({ error: 'Forbidden' }, { status: 403 })
    }

    return null // Allow through
  }
}
