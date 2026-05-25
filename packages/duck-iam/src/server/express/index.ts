import type { Engine } from '../../core'
import type { AccessControl, Request } from '../../core/types'
import {
  type AdminAudit,
  defaultCsrfCheck,
  extractEnvironment,
  METHOD_ACTION_MAP,
  noticeCsrfDefaultIfNeeded,
  runAdminAuthz,
  withAdminAudit,
} from '../generic'

/** Minimal Express request shape. */
interface Req {
  method?: string
  path?: string
  url?: string
  ip?: string
  params?: Record<string, string>
  headers?: Record<string, string | string[] | undefined>
  body?: unknown
  user?: { id: string; [k: string]: unknown }
  [k: string]: unknown
}
/** Minimal Express response shape. */
interface Res {
  status(code: number): Res
  json(body: unknown): void
}
/** Express next function. */
type Next = (err?: unknown) => void
/** Express middleware function. */
type Middleware = (req: Req, res: Res, next: Next) => void

/** Minimal Express Router interface for admin routes. */
interface ExpressRouterLike {
  get(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  put(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  post(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  delete(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
}

/**
 * Express server integration types. Type-only namespace - zero bundle cost.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export namespace Express {
  /**
   * Describes options for {@link accessMiddleware} and {@link guard}.
   *
   * Every extractor has a sensible default; override only what your app needs.
   *
   * @template TScope - Constrains valid scope strings.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IOptions<TScope extends string = string> {
    /** Extracts the current user ID from the request. */
    getUserId?: (req: Req) => string | null
    /** Derives the target resource from the request. */
    getResource?: (req: Req) => Request.IResource
    /** Derives the action being performed from the request. */
    getAction?: (req: Req) => string
    /** Extracts environment context (IP, user-agent, etc.) from the request. */
    getEnvironment?: (req: Req) => Request.IEnvironment
    /** Determines the scope used for the access check. */
    getScope?: (req: Req) => TScope | undefined
    /** Handles a denied request (defaults to 403 JSON). */
    onDenied?: (req: Req, res: Res) => void
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, req: Req, res: Res, next: Next) => void
  }

  /**
   * Required guard callback for admin endpoints.
   *
   * Returning `false` (or throwing) blocks the mutation; returning `true` lets it
   * proceed. The admin router writes policies, roles, and assignments directly
   * to the adapter; mounting it without auth has historically been the most
   * common foot-gun in authorization systems, so this hook is mandatory.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export type IAdminAuthorize = (req: Req) => boolean | Promise<boolean>

  /**
   * Describes options for {@link adminRouter}. `authorize` is required.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IAdminRouterOptions extends AdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (req: Req, res: Res) => void
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, req: Req, res: Res) => void
    /**
     * SEC-010: optional audit hook fired AFTER every mutation handler
     * (PUT/POST/DELETE/PATCH) completes — success or failure. The hook is
     * fire-and-forget: a slow or throwing implementation never blocks the
     * request and can never alter the response. GET handlers do not fire it.
     *
     * See {@link AdminAudit.IOptions} (extended) for additional hardening
     * knobs: `redactPath` (SEC-039), `onAuditHookError` (SEC-040), and
     * `includeErrorMessage` (SEC-041).
     */
    onAdminMutation?: AdminAudit.Hook
  }
}

/**
 * @deprecated Use {@link Express.IOptions}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IExpressOptions<TScope extends string = string> = Express.IOptions<TScope>

/**
 * Builds global Express middleware that runs `engine.can(...)` on every request.
 *
 * Replies 401 when no user is present and 403 when denied.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param opts - Configures extractors and error hooks.
 * @returns An Express middleware function.
 * @example
 * ```ts
 * app.use(accessMiddleware(engine, {
 *   getUserId: (req) => req.user?.id ?? null,
 * }))
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function accessMiddleware<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: Engine<TAction, TResource, TRole, TScope>, opts: Express.IOptions<TScope> = {}): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getResource = (req) => {
      const parts = (req.path ?? '/').split('/').filter(Boolean)
      return { type: parts[0] ?? 'root', id: parts[1], attributes: {} }
    },
    getAction = (req) => METHOD_ACTION_MAP[req.method ?? 'GET'] ?? 'read',
    getEnvironment = extractEnvironment,
    getScope,
    onDenied = (_, res) => res.status(403).json({ error: 'Forbidden' }),
    onError = (_err, _, res) => res.status(500).json({ error: 'Internal server error' }),
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
        getAction(req) as TAction,
        getResource(req) as Request.IResource<TResource>,
        getEnvironment(req),
        getScope?.(req),
      )
      allowed ? next() : onDenied(req, res)
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)), req, res, next)
    }
  }
}

/**
 * Builds per-route middleware that checks `(action, resourceType)` for the
 * current user, pulling the resource ID from `req.params.id`.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param action - Specifies the action being performed.
 * @param resourceType - Specifies the resource type required for the check.
 * @param opts - Configures optional extractors and `scope` override.
 * @returns An Express middleware function.
 * @example
 * ```ts
 * app.delete('/posts/:id', guard(engine, 'delete', 'post'), handler)
 * app.post('/admin/users', guard(engine, 'manage', 'user', { scope: 'admin' }), handler)
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
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
  opts: Pick<Express.IOptions<TScope>, 'getUserId' | 'getEnvironment' | 'onDenied'> & { scope?: TScope } = {},
): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getEnvironment = extractEnvironment,
    onDenied = (_, res) => res.status(403).json({ error: 'Forbidden' }),
    scope,
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
        scope,
      )
      allowed ? next() : onDenied(req, res)
    } catch (err) {
      next(err)
    }
  }
}

/**
 * @deprecated Use {@link Express.IAdminAuthorize}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IAdminAuthorize = Express.IAdminAuthorize

/**
 * @deprecated Use {@link Express.IAdminRouterOptions}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IAdminRouterOptions = Express.IAdminRouterOptions

/**
 * Builds an Express router for the duck-iam admin API.
 *
 * Returns a factory that accepts the Express `Router` constructor so we never
 * import express at runtime. Throws when `opts.authorize` is missing.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine whose `admin` operations are exposed.
 * @param opts - Must include `authorize`; mounting unauthenticated is rejected.
 * @returns A factory `(Router) => router` that wires admin endpoints.
 * @throws Error when `opts.authorize` is not a function.
 * @example
 * ```ts
 * import { Router } from 'express'
 * app.use('/api/access-admin', adminRouter(engine, {
 *   authorize: (req) => req.user?.role === 'admin',
 *   onAdminMutation: (e) => auditLog.write(e), // SEC-010 audit trail
 * })(Router))
 * ```
 * @example
 * Rate limiting is out of scope; compose at the mount point with the
 * caller's library of choice — `express-rate-limit` is the canonical pick:
 * ```ts
 * import rateLimit from 'express-rate-limit'
 * const adminLimiter = rateLimit({ windowMs: 60_000, max: 30 })
 * app.use('/api/access-admin', adminLimiter, adminRouter(engine, { authorize })(Router))
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function adminRouter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: Engine<TAction, TResource, TRole, TScope>,
  opts: Express.IAdminRouterOptions,
): (Router: () => ExpressRouterLike) => ExpressRouterLike {
  if (!opts || typeof opts.authorize !== 'function') {
    throw new Error(
      '[duck-iam] adminRouter requires an `authorize` callback. Mounting admin endpoints unauthenticated is never safe.',
    )
  }
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  const onUnauthorized = opts.onUnauthorized ?? ((_, res) => res.status(401).json({ error: 'Unauthorized' }))
  const onError = opts.onError ?? ((_, __, res) => res.status(500).json({ error: 'Internal server error' }))
  const onForbidden = (res: Res) => res.status(403).json({ error: 'Forbidden (CSRF check failed)' })
  // SEC-103: default to built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? defaultCsrfCheck)
  noticeCsrfDefaultIfNeeded(csrfCheck !== undefined)

  /** Read gate: no audit emission. */
  const gate = (handler: (req: Req, res: Res) => Promise<void>) => async (req: Req, res: Res) => {
    try {
      if (!(await authorize(req))) {
        onUnauthorized(req, res)
        return
      }
      await handler(req, res)
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)), req, res)
    }
  }

  /**
   * SEC-010 mutation gate: identical to {@link gate} but emits an
   * `onAdminMutation` event after the handler resolves or rejects. Uses
   * try/finally so the hook fires even when the handler throws.
   */
  const mutate =
    (
      action: AdminAudit.Action,
      target: AdminAudit.Target,
      getTargetId: ((req: Req) => string | undefined) | undefined,
      handler: (req: Req, res: Res) => Promise<void>,
    ) =>
    async (req: Req, res: Res) => {
      // DEBT-4: shared CSRF + authorize phase.
      const authz = await runAdminAuthz(req, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') return onForbidden(res)
      if (authz.phase === 'unauthorized') return onUnauthorized(req, res)
      if (authz.phase === 'error') return onError(authz.error, req, res)
      try {
        await withAdminAudit(
          {
            actor: authz.actor,
            action,
            target,
            targetId: getTargetId?.(req),
            method: req.method ?? '',
            path: req.path ?? req.url ?? '',
            onAdminMutation,
            redactPath,
            onAuditHookError,
            includeErrorMessage,
          },
          () => handler(req, res),
        )
      } catch (err) {
        onError(err instanceof Error ? err : new Error(String(err)), req, res)
      }
    }

  return (Router: () => ExpressRouterLike) => {
    const router = Router()

    router.get(
      '/policies',
      gate(async (_, res) => {
        res.json(await engine.admin.listPolicies())
      }),
    )

    router.get(
      '/roles',
      gate(async (_, res) => {
        res.json(await engine.admin.listRoles())
      }),
    )

    router.put(
      '/policies',
      mutate(
        'replace',
        'policy',
        (req) => (req.body as { id?: string } | undefined)?.id,
        async (req, res) => {
          await engine.admin.savePolicy(req.body as AccessControl.IPolicy<TAction, TResource, TRole>)
          res.json({ ok: true })
        },
      ),
    )

    router.put(
      '/roles',
      mutate(
        'replace',
        'role',
        (req) => (req.body as { id?: string } | undefined)?.id,
        async (req, res) => {
          await engine.admin.saveRole(req.body as AccessControl.IRole<TAction, TResource, TRole, TScope>)
          res.json({ ok: true })
        },
      ),
    )

    router.post(
      '/subjects/:id/roles',
      mutate(
        'create',
        'role-assignment',
        (req) => req.params?.id,
        async (req, res) => {
          const body = req.body as Record<string, unknown>
          await engine.admin.assignRole(req.params?.id as string, body.roleId as TRole, body.scope as TScope)
          res.json({ ok: true })
        },
      ),
    )

    router.delete(
      '/subjects/:id/roles/:roleId',
      mutate(
        'delete',
        'role-assignment',
        (req) => req.params?.id,
        async (req, res) => {
          await engine.admin.revokeRole(req.params?.id as string, req.params?.roleId as TRole)
          res.json({ ok: true })
        },
      ),
    )

    return router
  }
}
