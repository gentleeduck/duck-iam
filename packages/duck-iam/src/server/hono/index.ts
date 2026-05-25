import type { Engine } from '../../core'
import type { AccessControl, Request } from '../../core/types'
import {
  type AdminAudit,
  defaultCsrfCheck,
  METHOD_ACTION_MAP,
  noticeCsrfDefaultIfNeeded,
  runAdminAuthz,
  withAdminAudit,
} from '../generic'

/** Minimal Hono context shape. */
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
/** Hono next function. */
type HonoNext = () => Promise<void>
/** Hono middleware function. */
type HonoMiddleware = (c: HonoContext, next: HonoNext) => Promise<Response | undefined>

/**
 * Hono server integration types. Type-only namespace - zero bundle cost.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export namespace Hono {
  /**
   * Describes options for the Hono {@link accessMiddleware} and {@link guard}.
   *
   * Every extractor has a sensible default.
   *
   * @template TScope - Constrains valid scope strings.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IOptions<TScope extends string = string> {
    /** Extracts the current user ID from the context. */
    getUserId?: (c: HonoContext) => string | null
    /** Derives the target resource from the context. */
    getResource?: (c: HonoContext) => Request.IResource
    /** Derives the action being performed from the context. */
    getAction?: (c: HonoContext) => string
    /** Extracts environment context (IP, user-agent, etc.) from the context. */
    getEnvironment?: (c: HonoContext) => Request.IEnvironment
    /** Determines the scope used for the access check. */
    getScope?: (c: HonoContext) => TScope | undefined
    /** Handles a denied request (defaults to 403 JSON). */
    onDenied?: (c: HonoContext) => Response
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, c: HonoContext) => Response
  }

  /**
   * Required guard callback for the Hono admin router.
   *
   * Returning `false` (or throwing) blocks the request.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export type IAdminAuthorize = (c: HonoContext) => boolean | Promise<boolean>

  /**
   * Describes options for {@link bindAdminRouter}. `authorize` is required.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IAdminOptions extends AdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (c: HonoContext) => Response
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, c: HonoContext) => Response
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

  /**
   * Describes the minimal Hono router surface used by {@link bindAdminRouter}.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IRouterLike {
    get(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
    put(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
    post(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
    delete(path: string, handler: (c: HonoContext) => Promise<Response> | Response): unknown
  }
}

/**
 * @deprecated Use {@link Hono.IOptions}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IHonoOptions<TScope extends string = string> = Hono.IOptions<TScope>

/** Extract environment from Hono context using common headers. */
function defaultEnv(c: HonoContext): Request.IEnvironment {
  return {
    ip: c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for'),
    userAgent: c.req.header('user-agent'),
    timestamp: Date.now(),
  }
}

/**
 * Builds Hono middleware that runs `engine.can(...)` on every request.
 *
 * Replies 401 when no user is present and 403 when denied.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param opts - Configures optional extractors and error hooks.
 * @returns A Hono middleware function.
 * @example
 * ```ts
 * app.use('*', accessMiddleware(engine, {
 *   getUserId: (c) => c.get('userId') as string | null,
 * }))
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function accessMiddleware<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: Engine<TAction, TResource, TRole, TScope>, opts: Hono.IOptions<TScope> = {}): HonoMiddleware {
  const {
    // SEC-101: never default to `c.req.header('x-user-id')` — any unauth client
    // can spoof that header. The default reads ONLY from `c.set('userId', ...)`
    // populated by upstream auth middleware. Operators wiring header-based
    // identity must opt in explicitly via `getUserId`.
    getUserId = (c) => (c.get('userId') as string | undefined) ?? null,
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
        getResource(c) as Request.IResource<TResource>,
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
 * @deprecated Use {@link Hono.IAdminAuthorize}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IHonoAdminAuthorize = Hono.IAdminAuthorize

/**
 * @deprecated Use {@link Hono.IAdminOptions}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IHonoAdminOptions = Hono.IAdminOptions

/**
 * @deprecated Use {@link Hono.IRouterLike}. Will be removed in 3.0.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export type IHonoRouterLike = Hono.IRouterLike

/**
 * Wires admin CRUD endpoints onto a Hono router.
 *
 * `authorize` is required and runs before every handler. Throws when the
 * callback is missing.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param router - Provides the existing Hono router instance.
 * @param engine - Provides the access engine whose `admin` operations are exposed.
 * @param opts - Must include `authorize`.
 * @returns The same router (chainable).
 * @throws Error when `opts.authorize` is not a function.
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * const admin = new Hono()
 * bindAdminRouter(admin, engine, {
 *   authorize: (c) => isAdmin(c),
 *   onAdminMutation: (e) => auditLog.write(e), // SEC-010 audit trail
 * })
 * app.route('/admin', admin)
 * ```
 * @example
 * Rate limiting is out of scope; compose at the mount point with a Hono
 * middleware before the admin sub-app. Pseudocode:
 * ```ts
 * import { rateLimit } from 'some-hono-rate-limit'
 * app.use('/admin/*', rateLimit({ windowMs: 60_000, max: 30 }))
 * app.route('/admin', admin)
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function bindAdminRouter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  router: Hono.IRouterLike,
  engine: Engine<TAction, TResource, TRole, TScope>,
  opts: Hono.IAdminOptions,
): Hono.IRouterLike {
  if (!opts || typeof opts.authorize !== 'function') {
    throw new Error('[duck-iam] bindAdminRouter requires an `authorize` callback.')
  }
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  // SEC-103: default to built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? defaultCsrfCheck)
  noticeCsrfDefaultIfNeeded(csrfCheck !== undefined)
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
   * SEC-010 mutation gate: identical to {@link gate} but emits an
   * `onAdminMutation` event after the handler resolves or rejects. Uses
   * try/finally so the hook fires even when the handler throws.
   */
  const mutate =
    (
      action: AdminAudit.Action,
      target: AdminAudit.Target,
      getTargetId: ((c: HonoContext) => string | undefined) | undefined,
      handler: (c: HonoContext) => Promise<Response> | Response,
    ) =>
    async (c: HonoContext): Promise<Response> => {
      // DEBT-4: shared CSRF + authorize phase.
      const authz = await runAdminAuthz(c, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') return c.json({ error: 'Forbidden (CSRF check failed)' }, 403)
      if (authz.phase === 'unauthorized') return onUnauthorized(c)
      if (authz.phase === 'error') return onError(authz.error, c)
      try {
        return await withAdminAudit(
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
      const body = (await (c as unknown as { req: { json(): Promise<unknown> } }).req.json()) as AccessControl.IPolicy<
        TAction,
        TResource,
        TRole
      >
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
        const body = (await (c as unknown as { req: { json(): Promise<unknown> } }).req.json()) as {
          roleId: TRole
          scope?: TScope
        }
        await engine.admin.assignRole(c.req.param('id') as string, body.roleId, body.scope)
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
 * Builds Hono middleware that checks `(action, resourceType)` for the current
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
 * @returns A Hono middleware function.
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
  opts: Pick<Hono.IOptions<TScope>, 'getUserId' | 'getEnvironment' | 'onDenied' | 'onError'> & { scope?: TScope } = {},
): HonoMiddleware {
  const {
    // SEC-101: never default to `c.req.header('x-user-id')` — any unauth client
    // can spoof that header. The default reads ONLY from `c.set('userId', ...)`
    // populated by upstream auth middleware. Operators wiring header-based
    // identity must opt in explicitly via `getUserId`.
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
