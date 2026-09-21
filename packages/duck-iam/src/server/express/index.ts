import type { IamEngine } from '../../core'
import type { AccessControl, IamPrimitives, IamRequest } from '../../core/types'
import { type IamValidationError, iamIsValidationError } from '../../shared/errors'
import {
  iamAsActionLiteral,
  iamAsRoleLiteral,
  iamAsScopeLiteral,
  iamResourceAtCallerType,
} from '../../shared/tenant-literals'
import {
  type IamAdminActor,
  type IamAdminAudit,
  type IamAdminAuthzAnswer,
  iamActionForMethod,
  iamAdminActorOptions,
  iamAuditIdOf,
  iamDefaultCsrfCheck,
  iamDefaultResource,
  iamExtractEnvironment,
  iamIsSubjectId,
  iamNoticeCsrfDefaultIfNeeded,
  iamOptionalStringField,
  iamRequirePathParam,
  iamRequireStringField,
  iamRunAdminAuthz,
  iamWithAdminAudit,
} from '../generic'

/** Minimal Express request shape. */
export interface Req {
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
export interface Res {
  status(code: number): Res
  json(body: unknown): void
}
/** Express next function. */
export type Next = (err?: unknown) => void
/** Express middleware function. */
export type Middleware = (req: Req, res: Res, next: Next) => void

/** Minimal Express Router interface for admin routes. */
export interface ExpressRouterLike {
  get(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  put(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  post(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
  delete(path: string, handler: (req: Req, res: Res) => void | Promise<void>): void
}

/** Express server integration types. Type-only namespace - zero bundle cost. */
export namespace IamExpress {
  /**
   * Options for {@link iamAccessMiddleware} and {@link iamGuard}; every extractor has a default.
   * WARN: `TScope` stays first, unlike the engine's order, so existing `IOptions<MyScope>` keeps binding the scope.
   *
   * @template TScope    - Constrains valid scope strings.
   * @template TAction   - Constrains what `getAction` may return.
   * @template TResource - Constrains what `getResource` may name.
   */
  export interface IOptions<
    TScope extends string = string,
    TAction extends string = string,
    TResource extends string = string,
  > {
    /** Extracts the current user ID from the request. */
    getUserId?: (req: Req) => string | null
    /** Derives the target resource from the request. */
    getResource?: (req: Req) => IamRequest.IResource<TResource>
    /** Derives the action being performed from the request. */
    getAction?: (req: Req) => TAction
    /** Extracts environment context (IP, user-agent, etc.) from the request. */
    getEnvironment?: (req: Req) => IamRequest.IEnvironment
    /** Determines the scope used for the access check. */
    getScope?: (req: Req) => TScope | undefined
    /** Handles a denied request (defaults to 403 JSON). */
    onDenied?: (req: Req, res: Res) => void
    /**
     * Handles thrown errors during evaluation (defaults to 500 JSON).
     * SECURITY: `next` is not passed: calling it would resume the request with no decision made (fail open).
     */
    onError?: (err: Error, req: Req, res: Res) => void
  }

  /**
   * Required admin gate: a falsy answer or a throw blocks the request, a truthy one lets it proceed.
   * Prefer returning the actor over `true`, so the audit event and the write itself record who acted; a string
   * answer also reaches `engine.admin`. See {@link IamAdminAuthzAnswer} and `getMutationActor`.
   */
  export type IAdminAuthorize = (req: Req) => IamAdminAuthzAnswer | Promise<IamAdminAuthzAnswer>

  /** Describes options for {@link iamAdminRouter}. `authorize` is required. */
  export interface IAdminRouterOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (req: Req, res: Res) => void
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, req: Req, res: Res) => void
    /** Audit hook fired after every mutation, on success or failure; see {@link IamAdminAudit}. */
    onAdminMutation?: IamAdminAudit.Hook
    /**
     * Names the caller for `engine.admin`, which reaches the adapter's `created_by` / `updated_by`.
     * A string `authorize` answer is forwarded without this; an object one names no one until this picks the field.
     */
    getMutationActor?: (actor: IamAdminActor) => string | undefined
  }
}

/**
 * Builds global Express middleware that runs `engine.can(...)` on every request: 401 without a user, 403 on deny.
 *
 * SECURITY: a rule reading `resource.attributes.*` sees only what `getResource` puts there, and it is synchronous:
 * attributes an earlier middleware already attached work, loading the row here does not.
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
>(
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  opts: IamExpress.IOptions<NoInfer<TScope>, NoInfer<TAction>, NoInfer<TResource>> = {},
): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getResource = (req) => iamResourceAtCallerType<TResource>(iamDefaultResource(req.path)),
    getAction = (req) => iamAsActionLiteral<TAction>(iamActionForMethod(req.method)),
    getEnvironment = iamExtractEnvironment,
    getScope,
    onDenied = (_, res) => res.status(403).json({ error: 'Forbidden' }),
    onError = (_err, _, res) => res.status(500).json({ error: 'Internal server error' }),
  } = opts

  return async (req, res, next) => {
    try {
      // INFO: inside the try because `getUserId` may do I/O, and Express 4 answers nothing for a rejected
      // middleware promise, leaving the client to time out.
      const userId = getUserId(req)
      if (!iamIsSubjectId(userId)) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }

      const allowed = await engine.can(userId, getAction(req), getResource(req), getEnvironment(req), getScope?.(req))
      if (!allowed) {
        onDenied(req, res)
        return
      }
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)), req, res)
      return
    }
    // NOTE: outside the try, as in the hono and next guards, so a route's own error reaches Express's error
    // middleware rather than being answered here as an authorization failure.
    next()
  }
}

/**
 * Builds per-route middleware that checks `(action, resourceType)` for the
 * current user, pulling the resource ID from `req.params.id` unless `opts.getResourceId` names another source.
 *
 * SECURITY: a rule reading `resource.attributes.*` sees only what `getResourceAttributes` returns; without it the
 * resource is the route's type and id alone, and such a rule cannot fire.
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
  opts: Pick<IamExpress.IOptions<TScope>, 'getUserId' | 'getEnvironment' | 'onDenied' | 'onError'> & {
    scope?: TScope
    /**
     * The scope this check runs under, when the route names it (`/orgs/:orgId/...`). Consulted only when the static
     * `scope` is absent; without either, a scoped grant does not apply and a rule reading `scope` cannot fire.
     */
    getScope?: (req: Req) => TScope | undefined
    /**
     * The instance this check is about. The default reads the `:id` path param, which names the wrong row on a route
     * whose own id sits under another name (`/orgs/:id/posts/:postId`).
     */
    getResourceId?: (req: Req) => string | undefined
    /**
     * The resource's own attributes for this check; receives the request and the resolved tuple.
     * Declared here, not on {@link IamExpress.IOptions}, because `iamAccessMiddleware` takes them from `getResource`.
     */
    getResourceAttributes?: (
      req: Req,
      ctx: { action: TAction; resource: TResource; resourceId: string | undefined; scope: TScope | undefined },
    ) => Readonly<IamPrimitives.Attributes> | Promise<Readonly<IamPrimitives.Attributes>>
  } = {},
): Middleware {
  const {
    getUserId = (req) => req.user?.id ?? null,
    getEnvironment = iamExtractEnvironment,
    onDenied = (_, res) => res.status(403).json({ error: 'Forbidden' }),
    // SECURITY: a fixed 500 body, not `next(err)`: without an app error handler, express's finalhandler writes
    // `err.stack` into the response outside production.
    onError = (_err, _, res) => res.status(500).json({ error: 'Internal server error' }),
    getResourceAttributes,
    getResourceId = (req: Req) => req.params?.id,
    getScope,
    scope: staticScope,
  } = opts

  return async (req, res, next) => {
    try {
      const userId = getUserId(req)
      if (!iamIsSubjectId(userId)) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }

      const scope = staticScope ?? getScope?.(req)
      const resourceId = getResourceId(req)
      const attributes = getResourceAttributes
        ? await getResourceAttributes(req, { action, resource: resourceType, resourceId, scope })
        : {}
      const allowed = await engine.can(
        userId,
        action,
        { type: resourceType, id: resourceId, attributes },
        getEnvironment(req),
        scope,
      )
      if (!allowed) {
        onDenied(req, res)
        return
      }
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)), req, res)
      return
    }
    // NOTE: outside the try, for the same reason as the middleware above.
    next()
  }
}

/**
 * Builds an Express router for the duck-iam admin API, as a factory taking `Router` so express is never imported.
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
 * Rate limiting is out of scope; compose it at the mount point, e.g. with `express-rate-limit`:
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
      '[@gentleduck/iam:express] iamAdminRouter requires an `authorize` callback. Mounting admin endpoints unauthenticated is never safe.',
    )
  }
  const { authorize, onAdminMutation, getMutationActor, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } =
    opts
  const onUnauthorized = opts.onUnauthorized ?? ((_, res) => res.status(401).json({ error: 'Unauthorized' }))
  const onError = opts.onError ?? ((_, __, res) => res.status(500).json({ error: 'Internal server error' }))
  const onForbidden = (res: Res) => res.status(403).json({ error: 'Forbidden (CSRF check failed)' })
  const onBadRequest = (res: Res, err: IamValidationError) =>
    res.status(400).json({ error: `Invalid ${err.kind}`, issues: err.issues })
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)

  /**
   * Read gate: the same CSRF and `authorize` phase as {@link mutate}, with no audit event.
   * NOTE: CSRF runs on reads too, so an operator's `csrfCheck` is enforced alike on all four adapters.
   */
  const gate = (handler: (req: Req, res: Res) => Promise<void>) => async (req: Req, res: Res) => {
    const authz = await iamRunAdminAuthz(req, effectiveCsrfCheck, authorize)
    if (authz.phase === 'forbidden') return onForbidden(res)
    if (authz.phase === 'unauthorized') return onUnauthorized(req, res)
    if (authz.phase === 'error') return onError(authz.error, req, res)
    try {
      await handler(req, res)
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)), req, res)
    }
  }

  /** Mutation gate: the CSRF and `authorize` phase, then an `onAdminMutation` event on success or failure. */
  const mutate =
    (
      action: IamAdminAudit.Action,
      target: IamAdminAudit.Target,
      getTargetId: ((req: Req) => string | undefined) | undefined,
      handler: (req: Req, res: Res, who: { actor?: string }) => Promise<void>,
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
          () => handler(req, res, iamAdminActorOptions(authz.actor, getMutationActor)),
        )
      } catch (err) {
        // A rejected body is the caller's mistake: answer 400, since a 500 invites retrying what can never succeed.
        if (iamIsValidationError(err)) return onBadRequest(res, err)
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
        // NOTE: not a cast on `body.id`: the event fires even for a refused policy, so the id needs its own check.
        (req) => iamAuditIdOf(req.body),
        async (req, res, who) => {
          // The document is not checked here: `savePolicy` validates it before writing.
          await engine.admin.savePolicy(req.body as AccessControl.IPolicy<TAction, TResource, TRole>, who)
          res.json({ ok: true })
        },
      ),
    )

    router.put(
      '/roles',
      mutate(
        'replace',
        'role',
        // See the note on `PUT /policies` above.
        (req) => iamAuditIdOf(req.body),
        async (req, res, who) => {
          await engine.admin.saveRole(req.body as AccessControl.IRole<TAction, TResource, TRole, TScope>, who)
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
        async (req, res, who) => {
          const scope = iamOptionalStringField(req.body, 'scope')
          await engine.admin.assignRole(
            iamRequirePathParam(req.params?.id, 'id'),
            iamAsRoleLiteral<TRole>(iamRequireStringField(req.body, 'roleId')),
            scope === undefined ? undefined : iamAsScopeLiteral<TScope>(scope),
            who,
          )
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
        async (req, res, who) => {
          await engine.admin.revokeRole(
            iamRequirePathParam(req.params?.id, 'id'),
            iamAsRoleLiteral<TRole>(iamRequirePathParam(req.params?.roleId, 'roleId')),
            undefined,
            who,
          )
          res.json({ ok: true })
        },
      ),
    )

    return router
  }
}
