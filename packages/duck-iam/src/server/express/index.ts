import type { Engine } from '../../core/engine'
import type { Environment, Resource } from '../../core/types'
import { extractEnvironment, METHOD_ACTION_MAP } from '../generic'

// Minimal Express types to avoid hard dependency
interface Req {
  method?: string
  path?: string
  url?: string
  ip?: string
  params?: Record<string, string>
  headers?: Record<string, string | string[] | undefined>
  user?: { id: string; [k: string]: any }
  [k: string]: any
}
interface Res {
  status(code: number): Res
  json(body: any): void
}
type Next = (err?: any) => void
type Middleware = (req: Req, res: Res, next: Next) => void

export interface ExpressOptions {
  getUserId?: (req: Req) => string | null
  getResource?: (req: Req) => Resource
  getAction?: (req: Req) => string
  getEnvironment?: (req: Req) => Environment
  onDenied?: (req: Req, res: Res) => void
  onError?: (err: Error, req: Req, res: Res, next: Next) => void
}

/**
 * Global middleware: checks every request against the access engine.
 *
 *   app.use(accessMiddleware(engine, {
 *     getUserId: (req) => req.user?.id,
 *   }));
 */
export function accessMiddleware(engine: Engine, opts: ExpressOptions = {}): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getResource = (req) => {
      const parts = (req.path ?? '/').split('/').filter(Boolean)
      return { type: parts[0] ?? 'root', id: parts[1], attributes: {} }
    },
    getAction = (req) => METHOD_ACTION_MAP[req.method ?? 'GET'] ?? 'read',
    getEnvironment = extractEnvironment,
    onDenied = (_, res) => res.status(403).json({ error: 'Forbidden' }),
    onError = (err, _, res) => res.status(500).json({ error: 'Internal server error' }),
  } = opts

  return async (req, res, next) => {
    const userId = getUserId(req)
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    try {
      const allowed = await engine.can(userId, getAction(req), getResource(req), getEnvironment(req))
      allowed ? next() : onDenied(req, res)
    } catch (err) {
      onError(err as Error, req, res, next)
    }
  }
}

/**
 * Per-route guard.
 *
 *   app.delete("/posts/:id", guard(engine, "delete", "post"), handler);
 *   app.post("/admin/users", guard(engine, "manage", "user"), handler);
 */
export function guard(
  engine: Engine,
  action: string,
  resourceType: string,
  opts: Pick<ExpressOptions, 'getUserId' | 'getEnvironment' | 'onDenied'> = {},
): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getEnvironment = extractEnvironment,
    onDenied = (_, res) => res.status(403).json({ error: 'Forbidden' }),
  } = opts

  return async (req, res, next) => {
    const userId = getUserId(req)
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    try {
      const allowed = await engine.can(
        userId,
        action,
        { type: resourceType, id: req.params?.id, attributes: {} },
        getEnvironment(req),
      )
      allowed ? next() : onDenied(req, res)
    } catch (err) {
      next(err)
    }
  }
}

/**
 * Express router for admin API endpoints.
 * Mount at e.g. /api/access-admin
 *
 *   import { Router } from "express";
 *   app.use("/api/access-admin", adminRouter(engine));
 */
export function adminRouter(engine: Engine): any {
  // Returns a function that takes Router as arg to avoid importing express
  return (Router: any) => {
    const router = Router()

    router.get('/policies', async (_: Req, res: Res) => {
      res.json(await engine.admin.listPolicies())
    })

    router.get('/roles', async (_: Req, res: Res) => {
      res.json(await engine.admin.listRoles())
    })

    router.put('/policies', async (req: Req, res: Res) => {
      await engine.admin.savePolicy(req.body)
      res.json({ ok: true })
    })

    router.put('/roles', async (req: Req, res: Res) => {
      await engine.admin.saveRole(req.body)
      res.json({ ok: true })
    })

    router.post('/subjects/:id/roles', async (req: Req, res: Res) => {
      await engine.admin.assignRole(req.params!.id, req.body.roleId, req.body.scope)
      res.json({ ok: true })
    })

    router.delete('/subjects/:id/roles/:roleId', async (req: Req, res: Res) => {
      await engine.admin.revokeRole(req.params!.id, req.params!.roleId)
      res.json({ ok: true })
    })

    return router
  }
}
