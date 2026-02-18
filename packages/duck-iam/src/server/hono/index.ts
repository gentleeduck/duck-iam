import type { Engine } from '../../core/engine'
import type { Environment, Resource } from '../../core/types'
import { METHOD_ACTION_MAP } from '../generic'

/**
 * Hono integration for access-engine.
 * Works with Cloudflare Workers, Deno, Bun, and Node.js.
 *
 * Usage:
 *   import { Hono } from "hono";
 *   import { accessMiddleware, guard } from "access-engine/server/hono";
 *
 *   const app = new Hono();
 *
 *   // Global
 *   app.use("*", accessMiddleware(engine, { getUserId: (c) => c.get("userId") }));
 *
 *   // Per-route
 *   app.delete("/posts/:id", guard(engine, "delete", "post"), (c) => { ... });
 */

// Minimal Hono-compatible types
interface HonoContext {
  req: {
    method: string
    path: string
    url: string
    header(name: string): string | undefined
    param(name: string): string | undefined
  }
  get(key: string): any
  set(key: string, value: any): void
  json(data: any, status?: number): Response
  text(data: string, status?: number): Response
}
type HonoNext = () => Promise<void>
type HonoMiddleware = (c: HonoContext, next: HonoNext) => Promise<Response | void>

export interface HonoOptions {
  getUserId?: (c: HonoContext) => string | null
  getResource?: (c: HonoContext) => Resource
  getAction?: (c: HonoContext) => string
  getEnvironment?: (c: HonoContext) => Environment
  onDenied?: (c: HonoContext) => Response
}

function defaultEnv(c: HonoContext): Environment {
  return {
    ip: c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for'),
    userAgent: c.req.header('user-agent'),
    timestamp: Date.now(),
  }
}

/**
 * Global middleware for Hono.
 */
export function accessMiddleware(engine: Engine, opts: HonoOptions = {}): HonoMiddleware {
  const {
    getUserId = (c) => c.get('userId') ?? c.req.header('x-user-id'),
    getResource = (c) => {
      const parts = c.req.path.split('/').filter(Boolean)
      return { type: parts[0] ?? 'root', id: parts[1], attributes: {} }
    },
    getAction = (c) => METHOD_ACTION_MAP[c.req.method] ?? 'read',
    getEnvironment = defaultEnv,
    onDenied = (c) => c.json({ error: 'Forbidden' }, 403),
  } = opts

  return async (c, next) => {
    const userId = getUserId(c)
    if (!userId) return c.json({ error: 'Unauthorized' }, 401)

    const allowed = await engine.can(userId, getAction(c), getResource(c), getEnvironment(c))

    if (!allowed) return onDenied(c)
    await next()
  }
}

/**
 * Per-route guard for Hono.
 *
 *   app.delete("/posts/:id", guard(engine, "delete", "post"), handler);
 */
export function guard(
  engine: Engine,
  action: string,
  resourceType: string,
  opts: Pick<HonoOptions, 'getUserId' | 'getEnvironment' | 'onDenied'> = {},
): HonoMiddleware {
  const {
    getUserId = (c) => c.get('userId') ?? c.req.header('x-user-id'),
    getEnvironment = defaultEnv,
    onDenied = (c) => c.json({ error: 'Forbidden' }, 403),
  } = opts

  return async (c, next) => {
    const userId = getUserId(c)
    if (!userId) return c.json({ error: 'Unauthorized' }, 401)

    const allowed = await engine.can(
      userId,
      action,
      { type: resourceType, id: c.req.param('id'), attributes: {} },
      getEnvironment(c),
    )

    if (!allowed) return onDenied(c)
    await next()
  }
}
