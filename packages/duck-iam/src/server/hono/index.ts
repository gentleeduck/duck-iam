import type { IamEngine } from '../../core'
import type { AccessControl, IamRequest } from '../../core/types'
import { iamIsValidationError } from '../../shared/errors'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'
import {
  type IamAdminAudit,
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
/**
 * A context the admin router can read a body from.
 *
 * Separate from {@link HonoContext} because only the admin router needs a body
 * parser: the access middleware never reads one, and a consumer testing it with
 * a hand-built context should not have to supply a `json()` it will never call.
 * The router reached this method through `c as unknown as { req: { json(): ...
 * } }` at three sites, which typed away nothing the real hono context lacks and
 * only hid that the interface was incomplete for this use.
 */
interface HonoAdminContext extends HonoContext {
  req: HonoContext['req'] & { json(): Promise<unknown> }
}

/** Hono next function. */
type HonoNext = () => Promise<void>
/** Hono middleware function. */
type HonoMiddleware = (c: HonoContext, next: HonoNext) => Promise<Response | undefined>

/** Hono server integration types. Type-only namespace - zero bundle cost. */
export namespace IamHono {
  /**
   * Describes options for the Hono {@link iamAccessMiddleware} and {@link iamGuard}.
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
    /**
     * Read `cf-connecting-ip` as the client IP. Off by default: the header is
     * only trustworthy when Cloudflare is the sole ingress, and a Hono app
     * exposed directly lets any client set it.
     */
    trustCloudflareHeaders?: boolean
  }

  /**
   * Required iamGuard callback for the Hono admin router.
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

  /**
   * Describes the minimal Hono router surface used by {@link iamBindAdminRouter}.
   *
   * The handlers take a context carrying hono's body parser, because the admin
   * routes read request bodies. The access middleware's context type is
   * unchanged and still needs no parser.
   */
  export interface IRouterLike {
    get(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
    put(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
    post(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
    delete(path: string, handler: (c: HonoAdminContext) => Promise<Response> | Response): unknown
  }
}

/**
 * Extract environment from a Hono context.
 *
 * `environment.ip` stays `undefined` unless `trustCloudflareHeaders` is set,
 * and then it is `cf-connecting-ip` - a header Cloudflare overwrites on every
 * request, which is what makes it usable. `x-forwarded-for` and `x-real-ip`
 * are still passed through to {@link iamExtractEnvironment} so it can decide,
 * and it declines by default: with nothing in front of the app those are
 * headers the client sets itself, and reading them unconditionally let a plain
 * `X-Forwarded-For: 10.0.0.1` satisfy an IP-conditioned admin grant here.
 *
 * An app that terminates behind its own proxy supplies the value through
 * `opts.getEnvironment` instead.
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
    getResource = (c) => iamDefaultResource(c.req.path),
    getAction = (c) => iamActionForMethod(c.req.method),
    trustCloudflareHeaders = false,
    getEnvironment = (c: HonoContext) => defaultEnv(c, trustCloudflareHeaders),
    getScope,
    onDenied = (c) => c.json({ error: 'Forbidden' }, 403),
    onError = (_err, c) => c.json({ error: 'Internal server error' }, 500),
  } = opts

  return async (c, next) => {
    try {
      // Inside the try, like every other extractor: a throwing `getUserId` must
      // reach `onError` rather than the framework's boundary.
      const userId = getUserId(c)
      if (!iamIsSubjectId(userId)) return c.json({ error: 'Unauthorized' }, 401)

      const allowed = await engine.can(
        userId,
        getAction(c) as TAction,
        getResource(c) as IamRequest.IResource<TResource>,
        getEnvironment(c),
        getScope?.(c),
      )

      if (!allowed) return onDenied(c)
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), c)
    }
    // Outside the try, deliberately. Express / nest / next never wrap the
    // downstream handler; hono did, so a business-logic error thrown by the
    // route reached this middleware's `onError` - documented as "handles thrown
    // errors during evaluation" - and pre-empted the app's own `app.onError`.
    await next()
  }
}

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
 * iamBindAdminRouter(admin, engine, {
 *   authorize: (c) => isAdmin(c),
 *   onAdminMutation: (e) => auditLog.write(e),
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
   * Read gate. Runs the same CSRF + `authorize` phase as {@link mutate}, and
   * emits no audit event - a read is not a mutation.
   *
   * The CSRF check used to be skipped here on express, hono and next while nest
   * ran it, so `GET /policies` with `Sec-Fetch-Site: cross-site` returned the
   * full policy list on three adapters and 403 on the fourth. A browser cannot
   * read a cross-origin response without CORS, so that was not an exploitable
   * read - but `csrfCheck` is an operator-supplied predicate, and an operator
   * whose predicate carries any part of an authorization decision had it
   * enforced on reads on exactly one of four adapters, undocumented. The four
   * now answer the same question the same way.
   *
   * Not a new refusal for API clients: `iamDefaultCsrfCheck` returns `true`
   * when there is no `Sec-Fetch-Site` header at all, which is every non-browser
   * caller. What is now refused is a genuine cross-site browser read, and
   * `csrfCheck: false` still turns the whole phase off.
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

  /**
   * Mutation gate: unlike {@link gate} it runs the CSRF check first, then emits
   * an `onAdminMutation` audit event whether the handler resolves or rejects.
   */
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
      // Mutable, and read by `iamWithAdminAudit` in its `finally` rather than
      // at call time. `getTargetId` can only see the request, which is enough
      // for a role assignment (the subject is in the path) and useless for
      // `PUT /policies`, where the id is in a body nobody has parsed yet - so
      // those two events recorded that *a* policy had been replaced without
      // saying which one. The handler fills it in once it knows.
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
      // Shape-checked by `savePolicy`, which runs the validator before it
      // writes and throws `IamValidationError` - the same 400 this router
      // already answers for. Express, next and nest all read the body the same
      // way for the same reason.
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
        // These checks were hand-rolled here, with a 128-char cap the other
        // three adapters and the engine itself did not share, so the same
        // `roleId` was a 400 on hono and a write everywhere else. The shared
        // validators are the same checks with one cap and one status code.
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
    // Outside the try, deliberately. Express / nest / next never wrap the
    // downstream handler; hono did, so a business-logic error thrown by the
    // route reached this middleware's `onError` - documented as "handles thrown
    // errors during evaluation" - and pre-empted the app's own `app.onError`.
    await next()
  }
}
