import type { IamEngine } from '../../core'
import type { AccessControl, IamRequest } from '../../core/types'
import { iamIsValidationError } from '../../shared/errors'
import {
  iamAsActionLiteral,
  iamAsRoleLiteral,
  iamAsScopeLiteral,
  iamResourceAtCallerType,
} from '../../shared/tenant-literals'
import {
  type IamAdminAudit,
  type IamAdminAuthzAnswer,
  iamActionForMethod,
  iamAuditIdOf,
  iamDefaultCsrfCheck,
  iamDefaultResource,
  iamExtractEnvironment,
  iamIsSubjectId,
  iamNoticeCsrfDefaultIfNeeded,
  iamOptionalStringField,
  iamReadJsonBody,
  iamRequirePathParam,
  iamRequireStringField,
  iamRunAdminAuthz,
  iamWithAdminAudit,
} from '../generic'

/** Minimal Hono context shape. */
export interface HonoContext {
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
/**
 * A context the admin router can read a body from.
 * NOTE: kept apart from {@link HonoContext} so a hand-built context for the access middleware needs no `json()`.
 */
interface HonoAdminContext extends HonoContext {
  req: HonoContext['req'] & { json(): Promise<unknown> }
}

/** Hono next function. */
export type HonoNext = () => Promise<void>
/** Hono middleware function. */
export type HonoMiddleware = (c: HonoContext, next: HonoNext) => Promise<Response | undefined>

/** Hono server integration types. Type-only namespace - zero bundle cost. */
export namespace IamHono {
  /**
   * Options for the Hono {@link iamAccessMiddleware} and {@link iamGuard}; every extractor has a default.
   *
   * @template TScope - Constrains valid scope strings.
   */
  export interface IOptions<
    TScope extends string = string,
    TAction extends string = string,
    TResource extends string = string,
  > {
    /** Extracts the current user ID from the context. */
    getUserId?: (c: HonoContext) => string | null
    /** Derives the target resource from the context. */
    getResource?: (c: HonoContext) => IamRequest.IResource<TResource>
    /** Derives the action being performed from the context. */
    getAction?: (c: HonoContext) => TAction
    /** Extracts environment context (IP, user-agent, etc.) from the context. */
    getEnvironment?: (c: HonoContext) => IamRequest.IEnvironment
    /** Determines the scope used for the access check. */
    getScope?: (c: HonoContext) => TScope | undefined
    /** Handles a denied request (defaults to 403 JSON). */
    onDenied?: (c: HonoContext) => Response
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, c: HonoContext) => Response
    /**
     * Reads `cf-connecting-ip` as the client IP. Off by default.
     * SECURITY: trust it only when Cloudflare is the sole ingress; on a directly exposed app any client can set it.
     */
    trustCloudflareHeaders?: boolean
  }

  /**
   * Required admin gate: a falsy answer or a throw blocks the request, a truthy one lets it proceed.
   * Prefer returning the actor over `true`, so the audit event records who acted; see {@link IamAdminAuthzAnswer}.
   */
  export type IAdminAuthorize = (c: HonoContext) => IamAdminAuthzAnswer | Promise<IamAdminAuthzAnswer>

  /** Describes options for {@link iamBindAdminRouter}. `authorize` is required. */
  export interface IAdminOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (c: HonoContext) => Response
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, c: HonoContext) => Response
    /** Audit hook fired after every mutation, on success or failure; see {@link IamAdminAudit}. */
    onAdminMutation?: IamAdminAudit.Hook
  }

  /** The minimal Hono router surface {@link iamBindAdminRouter} uses; handlers get a context with a body parser. */
  export interface IRouterLike {
    get(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
    put(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
    post(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
    delete(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
  }
}

/**
 * Extracts the environment from a Hono context; apps behind their own proxy supply `ip` via `getEnvironment`.
 * SECURITY: `ip` is `undefined` unless `trustCloudflareHeaders` is set, since forwarding headers are client-set.
 */
function defaultEnv(c: HonoContext, trustCloudflareHeaders = false): IamRequest.IEnvironment {
  return iamExtractEnvironment(
    {
      ip: trustCloudflareHeaders ? c.req.header('cf-connecting-ip') : undefined,
      headers: {
        'x-forwarded-for': c.req.header('x-forwarded-for'),
        'x-real-ip': c.req.header('x-real-ip'),
        'user-agent': c.req.header('user-agent'),
      },
      method: c.req.method,
      url: c.req.url,
    },
    { trustProxy: trustCloudflareHeaders },
  )
}

/**
 * Builds Hono middleware that runs `engine.can(...)` on every request: 401 without a user, 403 on deny.
 *
 * SECURITY: the resource is built from the route, so `attributes` is empty and a rule reading
 * `resource.attributes.*` cannot fire here; re-check with `can()` once the handler has the row.
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
>(
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  opts: IamHono.IOptions<NoInfer<TScope>, NoInfer<TAction>, NoInfer<TResource>> = {},
): HonoMiddleware {
  const {
    // Read only from upstream-set `c.get('userId')`; never trust client headers.
    getUserId = (c) => (c.get('userId') as string | undefined) ?? null,
    getResource = (c) => iamResourceAtCallerType<TResource>(iamDefaultResource(c.req.path)),
    getAction = (c) => iamAsActionLiteral<TAction>(iamActionForMethod(c.req.method)),
    trustCloudflareHeaders = false,
    getEnvironment = (c: HonoContext) => defaultEnv(c, trustCloudflareHeaders),
    getScope,
    onDenied = (c) => c.json({ error: 'Forbidden' }, 403),
    onError = (_err, c) => c.json({ error: 'Internal server error' }, 500),
  } = opts

  return async (c, next) => {
    try {
      // Inside the try, like every other extractor, so a throwing `getUserId` reaches `onError`.
      const userId = getUserId(c)
      if (!iamIsSubjectId(userId)) return c.json({ error: 'Unauthorized' }, 401)

      const allowed = await engine.can(userId, getAction(c), getResource(c), getEnvironment(c), getScope?.(c))

      if (!allowed) return onDenied(c)
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), c)
    }
    // NOTE: outside the try, so a route's own error reaches the app's `app.onError`, not this `onError`.
    await next()
  }
}

/**
 * Wires admin CRUD endpoints onto a Hono router; the required `authorize` runs before every handler.
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
 * iamBindAdminRouter(admin, engine, {
 *   authorize: (c) => isAdmin(c),
 *   onAdminMutation: (e) => auditLog.write(e),
 * })
 * app.route('/admin', admin)
 * ```
 * @example
 * Rate limiting is out of scope; mount a Hono middleware before the admin sub-app (pseudocode):
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
    throw new Error('[@gentleduck/iam:hono] iamBindAdminRouter requires an `authorize` callback.')
  }
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)
  const onUnauthorized = opts.onUnauthorized ?? ((c) => c.json({ error: 'Unauthorized' }, 401))
  const onError = opts.onError ?? ((_, c) => c.json({ error: 'Internal server error' }, 500))

  /**
   * Read gate: the same CSRF and `authorize` phase as {@link mutate}, with no audit event.
   * NOTE: CSRF runs on reads too, so an operator's `csrfCheck` is enforced alike on all four adapters.
   */
  const gate =
    (handler: (c: HonoAdminContext) => Promise<Response> | Response) =>
    async (c: HonoAdminContext): Promise<Response> => {
      const authz = await iamRunAdminAuthz(c, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') return c.json({ error: 'Forbidden (CSRF check failed)' }, 403)
      if (authz.phase === 'unauthorized') return onUnauthorized(c)
      if (authz.phase === 'error') return onError(authz.error, c)
      try {
        return await handler(c)
      } catch (err) {
        return onError(err instanceof Error ? err : new Error(String(err)), c)
      }
    }

  /** Mutation gate: the CSRF and `authorize` phase, then an `onAdminMutation` event on success or failure. */
  const mutate =
    (
      action: IamAdminAudit.Action,
      target: IamAdminAudit.Target,
      getTargetId: ((c: HonoAdminContext) => string | undefined) | undefined,
      handler: (c: HonoAdminContext, setTargetId: (id: string | undefined) => void) => Promise<Response> | Response,
    ) =>
    async (c: HonoAdminContext): Promise<Response> => {
      // Shared CSRF + authorize phase.
      const authz = await iamRunAdminAuthz(c, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') return c.json({ error: 'Forbidden (CSRF check failed)' }, 403)
      if (authz.phase === 'unauthorized') return onUnauthorized(c)
      if (authz.phase === 'error') return onError(authz.error, c)
      // NOTE: mutable and read in `finally`, so a handler can set `targetId` once it has parsed the body
      // (`PUT /policies` and `/roles` carry the id there, not in the path).
      const auditCtx = {
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
      }
      try {
        return await iamWithAdminAudit(auditCtx, () =>
          Promise.resolve(
            handler(c, (id) => {
              auditCtx.targetId = id
            }),
          ),
        )
      } catch (err) {
        // A body the validator rejected is the caller's mistake, not ours.
        if (iamIsValidationError(err)) {
          return c.json({ error: `Invalid ${err.kind}`, issues: err.issues }, 400)
        }
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
    mutate('replace', 'policy', undefined, async (c, setTargetId) => {
      // Shape-checked by `savePolicy`, whose validator throws `IamValidationError`, answered here as 400.
      const body = (await iamReadJsonBody(() => c.req.json())) as AccessControl.IPolicy<TAction, TResource, TRole>
      setTargetId(iamAuditIdOf(body))
      await engine.admin.savePolicy(body)
      return c.json({ ok: true })
    }),
  )
  router.put(
    '/roles',
    mutate('replace', 'role', undefined, async (c, setTargetId) => {
      // Shape-checked by `saveRole`; see the note on `PUT /policies` above.
      const body = (await iamReadJsonBody(() => c.req.json())) as AccessControl.IRole<TAction, TResource, TRole, TScope>
      setTargetId(iamAuditIdOf(body))
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
        const raw: unknown = await iamReadJsonBody(() => c.req.json())
        const scope = iamOptionalStringField(raw, 'scope')
        await engine.admin.assignRole(
          iamRequirePathParam(c.req.param('id'), 'id'),
          iamAsRoleLiteral<TRole>(iamRequireStringField(raw, 'roleId')),
          scope === undefined ? undefined : iamAsScopeLiteral<TScope>(scope),
        )
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
        await engine.admin.revokeRole(
          iamRequirePathParam(c.req.param('id'), 'id'),
          iamAsRoleLiteral<TRole>(iamRequirePathParam(c.req.param('roleId'), 'roleId')),
        )
        return c.json({ ok: true })
      },
    ),
  )

  return router
}

/**
 * Builds Hono middleware that checks `(action, resourceType)` for the current user, with the id from `:id`.
 *
 * SECURITY: the resource is built from the route, so `attributes` is empty and a rule reading
 * `resource.attributes.*` cannot fire here; re-check with `can()` once the handler has the row.
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
  opts: Pick<
    IamHono.IOptions<TScope>,
    'getUserId' | 'getEnvironment' | 'onDenied' | 'onError' | 'trustCloudflareHeaders'
  > & {
    scope?: TScope
  } = {},
): HonoMiddleware {
  const {
    // Read only from upstream-set `c.get('userId')`; never trust client headers.
    getUserId = (c) => (c.get('userId') as string | undefined) ?? null,
    trustCloudflareHeaders = false,
    getEnvironment = (c: HonoContext) => defaultEnv(c, trustCloudflareHeaders),
    onDenied = (c) => c.json({ error: 'Forbidden' }, 403),
    onError = (_err, c) => c.json({ error: 'Internal server error' }, 500),
    scope,
  } = opts

  return async (c, next) => {
    try {
      const userId = getUserId(c)
      if (!iamIsSubjectId(userId)) return c.json({ error: 'Unauthorized' }, 401)

      const allowed = await engine.can(
        userId,
        action,
        { type: resourceType, id: c.req.param('id'), attributes: {} },
        getEnvironment(c),
        scope,
      )

      if (!allowed) return onDenied(c)
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), c)
    }
    // NOTE: outside the try, so a route's own error reaches the app's `app.onError`, not this `onError`.
    await next()
  }
}
