import type { Engine } from '../../core/engine'
import type { Environment, Resource } from '../../core/types'
import { METHOD_ACTION_MAP } from '../generic'

// Minimal Hono-compatible types -- no hard dependency on hono
interface HonoContext {
  req: {
    method: string
    path: string
    url: string
    header(name: string): string | undefined
    param(name: string): string | undefined
  }
  get(key: string): unknown
  set(key: string, value: unknown): void
  json(data: unknown, status?: number): Response
  text(data: string, status?: number): Response
}
type HonoNext = () => Promise<void>
type HonoMiddleware = (c: HonoContext, next: HonoNext) => Promise<Response | undefined>

export interface HonoOptions<TScope extends string = string> {
  getUserId?: (c: HonoContext) => string | null
  getResource?: (c: HonoContext) => Resource
  getAction?: (c: HonoContext) => string
  getEnvironment?: (c: HonoContext) => Environment
  getScope?: (c: HonoContext) => TScope | undefined
  onDenied?: (c: HonoContext) => Response
  onError?: (err: Error, c: HonoContext) => Response
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
export function accessMiddleware<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: Engine<TAction, TResource, TRole, TScope>, opts: HonoOptions<TScope> = {}): HonoMiddleware {
  const {
    getUserId = (c) => (c.get('userId') as string | undefined) ?? c.req.header('x-user-id') ?? null,
    getResource = (c) => {
      const parts = c.req.path.split('/').filter(Boolean)
      return { type: parts[0] ?? 'root', id: parts[1], attributes: {} }
    },
    getAction = (c) => METHOD_ACTION_MAP[c.req.method] ?? 'read',
    getEnvironment = defaultEnv,
    getScope,
    onDenied = (c) => c.json({ error: 'Forbidden' }, 403),
    onError = (_err, c) => c.json({ error: 'Internal server error' }, 500),
  } = opts

  return async (c, next) => {
    const userId = getUserId(c)
    if (!userId) return c.json({ error: 'Unauthorized' }, 401)

    try {
      const allowed = await engine.can(
        userId,
        getAction(c) as TAction,
        getResource(c) as Resource<TResource>,
        getEnvironment(c),
        getScope?.(c),
      )

      if (!allowed) return onDenied(c)
      await next()
    } catch (err) {
      return onError(err as Error, c)
    }
  }
}

/**
 * Per-route guard for Hono.
 *
 *   app.delete("/posts/:id", guard(engine, "delete", "post"), handler);
 *   app.post("/admin/users", guard(engine, "manage", "user", { scope: "admin" }), handler);
 */
export function guard<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: Engine<TAction, TResource, TRole, TScope>,
  action: TAction,
  resourceType: TResource,
  opts: Pick<HonoOptions<TScope>, 'getUserId' | 'getEnvironment' | 'onDenied' | 'onError'> & { scope?: TScope } = {},
): HonoMiddleware {
  const {
    getUserId = (c) => (c.get('userId') as string | undefined) ?? c.req.header('x-user-id') ?? null,
    getEnvironment = defaultEnv,
    onDenied = (c) => c.json({ error: 'Forbidden' }, 403),
    onError = (_err, c) => c.json({ error: 'Internal server error' }, 500),
    scope,
  } = opts

  return async (c, next) => {
    const userId = getUserId(c)
    if (!userId) return c.json({ error: 'Unauthorized' }, 401)

    try {
      const allowed = await engine.can(
        userId,
        action,
        { type: resourceType, id: c.req.param('id'), attributes: {} },
        getEnvironment(c),
        scope,
      )

      if (!allowed) return onDenied(c)
      await next()
    } catch (err) {
      return onError(err as Error, c)
    }
  }
}
