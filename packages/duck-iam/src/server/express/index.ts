import type { IamEngine } from '../../core'
import type { IamAccessControl, IamRequest } from '../../core/types'
import {
  type IamAdminAudit,
  iamDefaultCsrfCheck,
  iamExtractEnvironment,
  IAM_METHOD_ACTION_MAP,
  iamNoticeCsrfDefaultIfNeeded,
  iamRunAdminAuthz,
  iamWithAdminAudit,
} from '../generic'

/** Minimal IamExpress request shape. */
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
/** Minimal IamExpress response shape. */
interface Res {
  status(code: number): Res
  json(body: unknown): void
}
/** IamExpress next function. */
type Next = (err?: unknown) => void
/** IamExpress middleware function. */
type Middleware = (req: Req, res: Res, next: Next) => void

/** Minimal IamExpress Router interface for admin routes. */
interface ExpressRouterLike {
  get(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  put(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  post(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  delete(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
}

/** IamExpress server integration types. Type-only namespace - zero bundle cost. */
export namespace IamExpress {
  /**
   * Describes options for {@link iamAccessMiddleware} and {@link iamGuard}.
   *
   * Every extractor has a sensible default; override only what your app needs.
   *
   * @template TScope - Constrains valid scope strings.
   */
  export interface IOptions<TScope extends string = string> {
    /** Extracts the current user ID from the request. */
    getUserId?: (req: Req) => string | null
    /** Derives the target resource from the request. */
    getResource?: (req: Req) => IamRequest.IResource
    /** Derives the action being performed from the request. */
    getAction?: (req: Req) => string
    /** Extracts environment context (IP, user-agent, etc.) from the request. */
    getEnvironment?: (req: Req) => IamRequest.IEnvironment
    /** Determines the scope used for the access check. */
    getScope?: (req: Req) => TScope | undefined
    /** Handles a denied request (defaults to 403 JSON). */
    onDenied?: (req: Req, res: Res) => void
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, req: Req, res: Res, next: Next) => void
  }

  /**
   * Required iamGuard callback for admin endpoints.
   *
   * Returning `false` (or throwing) blocks the mutation; returning `true` lets it
   * proceed. The admin router writes policies, roles, and assignments directly
   * to the adapter; mounting it without auth has historically been the most
   * common foot-gun in authorization systems, so this hook is mandatory.
   */
  export type IAdminAuthorize = (req: Req) => boolean | Promise<boolean>

  /** Describes options for {@link iamAdminRouter}. `authorize` is required. */
  export interface IAdminRouterOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (req: Req, res: Res) => void
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, req: Req, res: Res) => void
    /**
     * Optional audit hook fired AFTER every mutation handler (PUT/POST/
     * DELETE/PATCH) completes - success or failure. The hook is
     * fire-and-forget: a slow or throwing implementation never blocks the
     * request and can never alter the response. GET handlers do not fire it.
     *
     * See {@link IamAdminAudit.IOptions} for additional hardening knobs:
     * `redactPath`, `onAuditHookError`, and `includeErrorMessage`.
     */
    onAdminMutation?: IamAdminAudit.Hook
  }
}

/**
 * Builds global IamExpress middleware that runs `engine.can(...)` on every request.
 *
 * Replies 401 when no user is present and 403 when denied.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param opts - Configures extractors and error hooks.
 * @returns An IamExpress middleware function.
 * @example
 * ```ts
 * app.use(iamAccessMiddleware(engine, {
 *   getUserId: (req) => req.user?.id ?? null,
 * }))
 * ```
 */
export function iamAccessMiddleware<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: IamEngine<TAction, TResource, TRole, TScope>, opts: IamExpress.IOptions<TScope> = {}): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getResource = (req) => {
      const parts = (req.path ?? '/').split('/').filter(Boolean)
      return { type: parts[0] ?? 'root', id: parts[1], attributes: {} }
    },
    getAction = (req) => IAM_METHOD_ACTION_MAP[req.method ?? 'GET'] ?? 'read',
    getEnvironment = iamExtractEnvironment,
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
        getResource(req) as IamRequest.IResource<TResource>,
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
 * @returns An IamExpress middleware function.
 * @example
 * ```ts
 * app.delete('/posts/:id', iamGuard(engine, 'delete', 'post'), handler)
 * app.post('/admin/users', iamGuard(engine, 'manage', 'user', { scope: 'admin' }), handler)
 * ```
 */
export function iamGuard<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  action: TAction,
  resourceType: TResource,
  opts: Pick<IamExpress.IOptions<TScope>, 'getUserId' | 'getEnvironment' | 'onDenied'> & { scope?: TScope } = {},
): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getEnvironment = iamExtractEnvironment,
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
 * Builds an IamExpress router for the duck-iam admin API.
 *
 * Returns a factory that accepts the IamExpress `Router` constructor so we never
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
 * app.use('/api/access-admin', iamAdminRouter(engine, {
 *   authorize: (req) => req.user?.role === 'admin',
 *   onAdminMutation: (e) => auditLog.write(e),
 * })(Router))
 * ```
 * @example
 * Rate limiting is out of scope; compose at the mount point with the
 * caller's library of choice - `express-rate-limit` is the canonical pick:
 * ```ts
 * import rateLimit from 'express-rate-limit'
 * const adminLimiter = rateLimit({ windowMs: 60_000, max: 30 })
 * app.use('/api/access-admin', adminLimiter, iamAdminRouter(engine, { authorize })(Router))
 * ```
 */
export function iamAdminRouter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  opts: IamExpress.IAdminRouterOptions,
): (Router: () => ExpressRouterLike) => ExpressRouterLike {
  if (!opts || typeof opts.authorize !== 'function') {
    throw new Error(
      '[@gentleduck/iam] iamAdminRouter requires an `authorize` callback. Mounting admin endpoints unauthenticated is never safe.',
    )
  }
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  const onUnauthorized = opts.onUnauthorized ?? ((_, res) => res.status(401).json({ error: 'Unauthorized' }))
  const onError = opts.onError ?? ((_, __, res) => res.status(500).json({ error: 'Internal server error' }))
  const onForbidden = (res: Res) => res.status(403).json({ error: 'Forbidden (CSRF check failed)' })
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)

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
   * Mutation gate: identical to {@link gate} but emits an `onAdminMutation`
   * event after the handler resolves or rejects. Uses try/finally so the
   * hook fires even when the handler throws.
   */
  const mutate =
    (
      action: IamAdminAudit.Action,
      target: IamAdminAudit.Target,
      getTargetId: ((req: Req) => string | undefined) | undefined,
      handler: (req: Req, res: Res) => Promise<void>,
    ) =>
    async (req: Req, res: Res) => {
      // Shared CSRF + authorize phase.
      const authz = await iamRunAdminAuthz(req, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') return onForbidden(res)
      if (authz.phase === 'unauthorized') return onUnauthorized(req, res)
      if (authz.phase === 'error') return onError(authz.error, req, res)
      try {
        await iamWithAdminAudit(
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
          await engine.admin.savePolicy(req.body as IamAccessControl.IPolicy<TAction, TResource, TRole>)
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
          await engine.admin.saveRole(req.body as IamAccessControl.IRole<TAction, TResource, TRole, TScope>)
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
