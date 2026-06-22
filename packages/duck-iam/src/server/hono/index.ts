import type { IamEngine } from '../../core'
import type { AccessControl, IamRequest } from '../../core/types'
import {
  IAM_METHOD_ACTION_MAP,
  type IamAdminAudit,
  iamDefaultCsrfCheck,
  iamNoticeCsrfDefaultIfNeeded,
  iamRunAdminAuthz,
  iamWithAdminAudit,
} from '../generic'

/** Minimal IamHono context shape. */
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
/** IamHono next function. */
type HonoNext = () => Promise<void>
/** IamHono middleware function. */
type HonoMiddleware = (c: HonoContext, next: HonoNext) => Promise<Response | undefined>

/** IamHono server integration types. Type-only namespace - zero bundle cost. */
export namespace IamHono {
  /**
   * Describes options for the IamHono {@link iamAccessMiddleware} and {@link iamGuard}.
   *
   * Every extractor has a sensible default.
   *
   * @template TScope - Constrains valid scope strings.
   */
  export interface IOptions<TScope extends string = string> {
    /** Extracts the current user ID from the context. */
    getUserId?: (c: HonoContext) => string | null
    /** Derives the target resource from the context. */
    getResource?: (c: HonoContext) => IamRequest.IResource
    /** Derives the action being performed from the context. */
    getAction?: (c: HonoContext) => string
    /** Extracts environment context (IP, user-agent, etc.) from the context. */
    getEnvironment?: (c: HonoContext) => IamRequest.IEnvironment
    /** Determines the scope used for the access check. */
    getScope?: (c: HonoContext) => TScope | undefined
    /** Handles a denied request (defaults to 403 JSON). */
    onDenied?: (c: HonoContext) => Response
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, c: HonoContext) => Response
  }

  /**
   * Required iamGuard callback for the IamHono admin router.
   *
   * Returning `false` (or throwing) blocks the request.
   */
  export type IAdminAuthorize = (c: HonoContext) => boolean | Promise<boolean>

  /** Describes options for {@link iamBindAdminRouter}. `authorize` is required. */
  export interface IAdminOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (c: HonoContext) => Response
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, c: HonoContext) => Response
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

  /** Describes the minimal IamHono router surface used by {@link iamBindAdminRouter}. */
  export interface IRouterLike {
    get(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
    put(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
    post(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
    delete(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
  }
}

/** Extract environment from IamHono context using common headers. */
function defaultEnv(c: HonoContext): IamRequest.IEnvironment {
  return {
    ip: c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for'),
    userAgent: c.req.header('user-agent'),
    timestamp: Date.now(),
  }
}

/**
 * Builds IamHono middleware that runs `engine.can(...)` on every request.
 *
 * Replies 401 when no user is present and 403 when denied.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param opts - Configures optional extractors and error hooks.
 * @returns A IamHono middleware function.
 * @example
 * ```ts
 * app.use('*', iamAccessMiddleware(engine, {
 *   getUserId: (c) => c.get('userId') as string | null,
 * }))
 * ```
 */
export function iamAccessMiddleware<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: IamEngine<TAction, TResource, TRole, TScope>, opts: IamHono.IOptions<TScope> = {}): HonoMiddleware {
  const {
    // Read only from upstream-set `c.get('userId')`; never trust client headers.
    getUserId = (c) => (c.get('userId') as string | undefined) ?? null,
    getResource = (c) => {
      const parts = c.req.path.split('/').filter(Boolean)
      return { type: parts[0] ?? 'root', id: parts[1], attributes: {} }
    },
    getAction = (c) => IAM_METHOD_ACTION_MAP[c.req.method] ?? 'read',
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
        getResource(c) as IamRequest.IResource<TResource>,
        getEnvironment(c),
        getScope?.(c),
      )

      if (!allowed) return onDenied(c)
      await next()
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), c)
    }
  }
}

/**
 * Wires admin CRUD endpoints onto a IamHono router.
 *
 * `authorize` is required and runs before every handler. Throws when the
 * callback is missing.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param router - Provides the existing IamHono router instance.
 * @param engine - Provides the access engine whose `admin` operations are exposed.
 * @param opts - Must include `authorize`.
 * @returns The same router (chainable).
 * @throws Error when `opts.authorize` is not a function.
 * @example
 * ```ts
 * import { IamHono } from 'hono'
 * const admin = new IamHono()
 * iamBindAdminRouter(admin, engine, {
 *   authorize: (c) => isAdmin(c),
 *   onAdminMutation: (e) => auditLog.write(e),
 * })
 * app.route('/admin', admin)
 * ```
 * @example
 * Rate limiting is out of scope; compose at the mount point with a IamHono
 * middleware before the admin sub-app. Pseudocode:
 * ```ts
 * import { rateLimit } from 'some-hono-rate-limit'
 * app.use('/admin/*', rateLimit({ windowMs: 60_000, max: 30 }))
 * app.route('/admin', admin)
 * ```
 */
export function iamBindAdminRouter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  router: IamHono.IRouterLike,
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  opts: IamHono.IAdminOptions,
): IamHono.IRouterLike {
  if (!opts || typeof opts.authorize !== 'function') {
    throw new Error('[@gentleduck/iam] iamBindAdminRouter requires an `authorize` callback.')
  }
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)
  const onUnauthorized = opts.onUnauthorized ?? ((c) => c.json({ error: 'Unauthorized' }, 401))
  const onError = opts.onError ?? ((_, c) => c.json({ error: 'Internal server error' }, 500))

  /** Read gate: no audit emission. */
  const gate =
    (handler: (c: HonoContext) => Promise<Response> | Response) =>
    async (c: HonoContext): Promise<Response> => {
      try {
        if (!(await authorize(c))) return onUnauthorized(c)
        return await handler(c)
      } catch (err) {
        return onError(err instanceof Error ? err : new Error(String(err)), c)
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
      getTargetId: ((c: HonoContext) => string | undefined) | undefined,
      handler: (c: HonoContext) => Promise<Response> | Response,
    ) =>
    async (c: HonoContext): Promise<Response> => {
      // Shared CSRF + authorize phase.
      const authz = await iamRunAdminAuthz(c, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') return c.json({ error: 'Forbidden (CSRF check failed)' }, 403)
      if (authz.phase === 'unauthorized') return onUnauthorized(c)
      if (authz.phase === 'error') return onError(authz.error, c)
      try {
        return await iamWithAdminAudit(
          {
            actor: authz.actor,
            action,
            target,
            targetId: getTargetId?.(c),
            method: c.req.method,
            path: c.req.path,
            onAdminMutation,
            redactPath,
            onAuditHookError,
            includeErrorMessage,
          },
          () => Promise.resolve(handler(c)),
        )
      } catch (err) {
        return onError(err instanceof Error ? err : new Error(String(err)), c)
      }
    }

  router.get(
    '/policies',
    gate(async (c) => c.json(await engine.admin.listPolicies())),
  )
  router.get(
    '/roles',
    gate(async (c) => c.json(await engine.admin.listRoles())),
  )
  router.put(
    '/policies',
    mutate('replace', 'policy', undefined, async (c) => {
      const body = (await (
        c as unknown as { req: { json(): Promise<unknown> } }
      ).req.json()) as AccessControl.IPolicy<TAction, TResource, TRole>
      await engine.admin.savePolicy(body)
      return c.json({ ok: true })
    }),
  )
  router.put(
    '/roles',
    mutate('replace', 'role', undefined, async (c) => {
      const body = (await (c as unknown as { req: { json(): Promise<unknown> } }).req.json()) as AccessControl.IRole<
        TAction,
        TResource,
        TRole,
        TScope
      >
      await engine.admin.saveRole(body)
      return c.json({ ok: true })
    }),
  )
  router.post(
    '/subjects/:id/roles',
    mutate(
      'create',
      'role-assignment',
      (c) => c.req.param('id'),
      async (c) => {
        const raw: unknown = await (c as unknown as { req: { json(): Promise<unknown> } }).req.json()
        if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
          return c.json({ error: 'invalid body' }, 400)
        }
        const roleId = Reflect.get(raw, 'roleId')
        const scope = Reflect.get(raw, 'scope')
        if (typeof roleId !== 'string' || roleId.length === 0 || roleId.length > 128) {
          return c.json({ error: 'invalid roleId' }, 400)
        }
        if (scope !== undefined && (typeof scope !== 'string' || scope.length === 0 || scope.length > 128)) {
          return c.json({ error: 'invalid scope' }, 400)
        }
        await engine.admin.assignRole(c.req.param('id') as string, roleId as TRole, scope as TScope | undefined)
        return c.json({ ok: true })
      },
    ),
  )
  router.delete(
    '/subjects/:id/roles/:roleId',
    mutate(
      'delete',
      'role-assignment',
      (c) => c.req.param('id'),
      async (c) => {
        await engine.admin.revokeRole(c.req.param('id') as string, c.req.param('roleId') as TRole)
        return c.json({ ok: true })
      },
    ),
  )

  return router
}

/**
 * Builds IamHono middleware that checks `(action, resourceType)` for the current
 * user, pulling the resource ID from the `:id` route param.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param action - Specifies the action being performed.
 * @param resourceType - Specifies the resource type required for the check.
 * @param opts - Configures optional extractors and `scope` override.
 * @returns A IamHono middleware function.
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
  opts: Pick<IamHono.IOptions<TScope>, 'getUserId' | 'getEnvironment' | 'onDenied' | 'onError'> & {
    scope?: TScope
  } = {},
): HonoMiddleware {
  const {
    // Read only from upstream-set `c.get('userId')`; never trust client headers.
    getUserId = (c) => (c.get('userId') as string | undefined) ?? null,
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
      return onError(err instanceof Error ? err : new Error(String(err)), c)
    }
  }
}
