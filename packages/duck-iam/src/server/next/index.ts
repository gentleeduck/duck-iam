/**
 * Next.js App Router integration: Route Handler wrappers, Server Component helpers, Middleware, and permission maps.
 */

import type { IamEngine } from '../../core'
import type { AccessControl, IamClient, IamPrimitives, IamRequest } from '../../core/types'
import { iamIsValidationError } from '../../shared/errors'
import { iamAsActionLiteral, iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'
import {
  type IamAdminActor,
  type IamAdminAudit,
  type IamAdminAuthzAnswer,
  iamActionForMethod,
  iamAdminActorOptions,
  iamAuditIdOf,
  iamDefaultCsrfCheck,
  iamExtractEnvironment,
  iamIsSubjectId,
  iamNormalizePathname,
  iamNoticeCsrfDefaultIfNeeded,
  iamOptionalStringField,
  iamPathIsAmbiguous,
  iamReadJsonBody,
  iamRequirePathParam,
  iamRequireStringField,
  iamRunAdminAuthz,
  iamWithAdminAudit,
} from '../generic'

/** Next.js route handler context with params. */
export type RouteContext = { params: Promise<Record<string, string>> | Record<string, string> }
/** Next.js App Router route handler signature. */
export type RouteHandler = (req: Request, ctx: RouteContext) => Promise<Response>

/** Next.js server integration types. Type-only namespace - zero bundle cost. */
export namespace IamNext {
  /**
   * Options for {@link withIamAccess}. `getUserId` is required at runtime; the rest have defaults.
   *
   * @template TScope - Constrains valid scope strings.
   */
  export interface IWithAccessOptions<TScope extends string = string> {
    /** Extracts the current user ID from the request. */
    getUserId?: (req: Request) => string | null | Promise<string | null>
    /** Extracts environment context (IP, user-agent, etc.) from the request. */
    getEnvironment?: (req: Request) => IamRequest.IEnvironment
    /** Applies a scope to the access check. */
    scope?: TScope
    /** The resource's own attributes for the check; receives the request and the resolved tuple. */
    getResourceAttributes?: (
      req: Request,
      ctx: { action: string; resource: string; resourceId: string | undefined; scope: TScope | undefined },
    ) => Readonly<IamPrimitives.Attributes> | Promise<Readonly<IamPrimitives.Attributes>>
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, req: Request) => Response
  }

  /**
   * Options for {@link createIamNextMiddleware}. `rules` and `getUserId` are required.
   *
   * @template TAction - Constrains valid action strings.
   * @template TResource - Constrains valid resource strings.
   * @template TScope - Constrains valid scope strings.
   */
  export interface IMiddlewareOptions<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    /** Maps URL patterns to required permissions. */
    rules: Array<{
      /** Specifies the regex or string prefix used to match the path. */
      pattern: string | RegExp
      /** Specifies the required action; inferred from HTTP method when omitted. */
      action?: TAction
      /** Specifies the resource type for this route. */
      resource: TResource
      /** Optional scope applied to the check. */
      scope?: TScope
    }>
    /** Extracts the current user ID from the request. */
    getUserId: (req: Request) => string | null | Promise<string | null>
    /** Extracts environment context (IP, user-agent, etc.) from the request. */
    getEnvironment?: (req: Request) => IamRequest.IEnvironment
    /** The resource's own attributes for the check; receives the request and the resolved tuple. */
    getResourceAttributes?: (
      req: Request,
      ctx: { action: TAction; resource: TResource; scope: TScope | undefined },
    ) => Readonly<IamPrimitives.Attributes> | Promise<Readonly<IamPrimitives.Attributes>>
    /** Handles a denied or ambiguous-path request (defaults to 403 JSON). */
    onDenied?: (req: Request) => Response
    /** Handles a request with no user (defaults to 401 JSON). */
    onUnauthorized?: (req: Request) => Response
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, req: Request) => Response
  }

  /**
   * Required admin gate: a falsy answer or a throw blocks the request, a truthy one lets it proceed.
   * Prefer returning the actor over `true`, so the audit event and the write itself record who acted; a string
   * answer also reaches `engine.admin`. See {@link IamAdminAuthzAnswer} and `getMutationActor`.
   */
  export type IAdminAuthorize = (req: Request) => IamAdminAuthzAnswer | Promise<IamAdminAuthzAnswer>

  /** Describes options for {@link createIamAdminHandlers}. `authorize` is required. */
  export interface IAdminOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (req: Request) => Response
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, req: Request) => Response
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
 * Wraps an App Router route handler with an access check: 401 without a user, 403 on deny, else the handler.
 * SECURITY: throws without `opts.getUserId`; identity never comes from request headers, which the caller controls.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param action - Specifies the action being performed.
 * @param resourceType - Specifies the resource type required for the check.
 * @param handler - The route handler invoked on allow; the resource id comes from `ctx.params.id`.
 * @param opts - `getUserId` (required), plus optional environment extractor, `scope`, and `onError`.
 * @returns A wrapped route handler.
 * @example
 * ```ts
 * export const DELETE = withIamAccess(
 *   engine,
 *   'delete',
 *   'post',
 *   async (req, ctx) => {
 *     const { id } = await ctx.params
 *     return Response.json({ deleted: id })
 *   },
 *   { getUserId: async () => (await auth()).userId },
 * )
 * ```
 */
export function withIamAccess<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  action: TAction,
  resourceType: TResource,
  handler: RouteHandler,
  opts: IamNext.IWithAccessOptions<TScope> = {},
): RouteHandler {
  // getUserId required; header-derived identity is spoofable.
  if (!opts.getUserId) {
    throw new Error(
      '[@gentleduck/iam:next] opts.getUserId is required - deriving identity from request headers is unsafe. ' +
        'Wire it from your auth middleware (cookie session, JWT, etc.).',
    )
  }
  const {
    getUserId,
    getEnvironment = (req) => iamExtractEnvironment({ headers: req.headers, method: req.method, url: req.url }),
    scope,
    onError = () => Response.json({ error: 'Internal server error' }, { status: 500 }),
    getResourceAttributes,
  } = opts

  return async (req, ctx) => {
    try {
      // Inside the try, like every other extractor, so a throwing `getUserId` reaches `onError`.
      const userId = await getUserId(req)
      if (!iamIsSubjectId(userId)) {
        return Response.json({ error: 'Unauthorized' }, { status: 401 })
      }

      const params = ctx.params instanceof Promise ? await ctx.params : ctx.params
      const resourceId = params?.id

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
        return Response.json({ error: 'Forbidden' }, { status: 403 })
      }

      return handler(req, ctx)
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), req)
    }
  }
}

/**
 * Whether `subjectId` can perform `(action, resourceType)`, for Server Components and server actions.
 *
 * SECURITY: `environment` and `attributes` default to absent, so a rule reading `environment.*` or
 * `resource.attributes.*` cannot fire unless this call passes them.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 */
export async function checkIamAccess<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  subjectId: string,
  action: TAction,
  resourceType: TResource,
  resourceId?: string,
  scope?: TScope,
  environment?: IamRequest.IEnvironment,
  attributes?: Readonly<IamPrimitives.Attributes>,
): Promise<boolean> {
  return engine.can(
    subjectId,
    action,
    {
      type: resourceType,
      id: resourceId,
      attributes: attributes ?? {},
    },
    environment,
    scope,
  )
}

/**
 * Builds a permission map in a Server Component or layout, to pass to the React `AccessProvider`.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @template TMode - Inferred from `engine`: a typed {@link IamClient.PermissionMap} in development, plain otherwise.
 * @returns A permission map keyed by `(action, resource, scope)` tuple.
 */
export async function getIamPermissions<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TMode extends AccessControl.Mode = AccessControl.Mode,
>(
  engine: IamEngine<TAction, TResource, TRole, TScope, TMode>,
  subjectId: string,
  checks: readonly IamClient.IPermissionCheck<TAction, TResource, TScope>[],
  environment?: IamRequest.IEnvironment,
): Promise<AccessControl.ModePermissionMap<TMode, TAction, TResource, TScope>> {
  return engine.permissions(subjectId, checks, environment)
}

/**
 * Builds a Next.js Middleware check from pattern-keyed rules: `null` when the request passes or no rule matches,
 * else a 401/403/500 `Response`.
 *
 * SECURITY: a rule reading `resource.attributes.*` sees only what `getResourceAttributes` returns; without it the
 * resource is the matched rule's type alone, and such a rule cannot fire.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param opts - Provides the rule list, user extractor, and optional error handler.
 * @returns An `async (req) => Response | null` suitable for use inside `middleware.ts`.
 * @example
 * ```ts
 * // NEVER trust user-supplied headers for identity. Derive from a verified
 * // source: cookie session, JWT, or your auth library.
 * const mw = createIamNextMiddleware(engine, {
 *   rules: [{ pattern: '/admin', resource: 'admin' }],
 *   getUserId: async (req) => {
 *     const session = await getServerSession(req)
 *     return session?.user?.id ?? null
 *   },
 * })
 * export const middleware = async (req: Request) => (await mw(req)) ?? NextResponse.next()
 * ```
 */
export function createIamNextMiddleware<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: IamEngine<TAction, TResource, TRole, TScope>, opts: IamNext.IMiddlewareOptions<TAction, TResource, TScope>) {
  // Same environment default as `withIamAccess`, so environment-conditioned rules behave alike.
  const {
    getEnvironment = (req: Request) =>
      iamExtractEnvironment({ headers: req.headers, method: req.method, url: req.url }),
    onDenied = () => Response.json({ error: 'Forbidden' }, { status: 403 }),
    onUnauthorized = () => Response.json({ error: 'Unauthorized' }, { status: 401 }),
    onError = () => Response.json({ error: 'Internal server error' }, { status: 500 }),
    getResourceAttributes,
  } = opts

  return async (req: Request): Promise<Response | null> => {
    const url = new URL(req.url)
    // SECURITY: refused before canonicalising: `/admin/..%2fpublic` would match a `/public` rule while next
    // serves `/admin`.
    if (iamPathIsAmbiguous(url.pathname)) {
      return onDenied(req)
    }
    // `//admin` and `/%61dmin` both survive `new URL()` and skip a `/admin`
    // rule while still routing to `/admin`. Match on the canonical form.
    const path = iamNormalizePathname(url.pathname)

    // SECURITY: a `%` left after one decode may be decoded again downstream, picking the wrong rule or none (which
    // passes unchecked), so refuse it as `iamDefaultResource` does.
    if (path.includes('%')) {
      return onDenied(req)
    }

    const matchedRule = opts.rules.find((r) => {
      if (typeof r.pattern === 'string') {
        return path.startsWith(r.pattern)
      }
      return r.pattern.test(path)
    })

    if (!matchedRule) return null

    try {
      // Inside the try, like every other extractor, so a throwing `getUserId` reaches `onError`.
      const userId = await opts.getUserId(req)
      if (!iamIsSubjectId(userId)) {
        return onUnauthorized(req)
      }

      // The method-inferred fallback is a runtime string that cannot be narrowed to the erased `TAction`, so it
      // widens through the named helper the other adapters use.
      const action: TAction = matchedRule.action ?? iamAsActionLiteral<TAction>(iamActionForMethod(req.method))

      const attributes = getResourceAttributes
        ? await getResourceAttributes(req, { action, resource: matchedRule.resource, scope: matchedRule.scope })
        : {}
      const allowed = await engine.can(
        userId,
        action,
        {
          type: matchedRule.resource,
          attributes,
        },
        getEnvironment(req),
        matchedRule.scope,
      )

      if (!allowed) {
        return onDenied(req)
      }

      return null
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), req)
    }
  }
}

/**
 * Builds pre-bound admin Route Handlers for the App Router; each runs the CSRF check and `authorize` first.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine whose `admin` operations are exposed.
 * @param opts - Must include `authorize`.
 * @returns Object with `listPolicies`, `listRoles`, `savePolicy`, `saveRole`, `assignRole`, `revokeRole`.
 * @throws Error when `opts.authorize` is not a function.
 * @example
 * ```ts
 * // app/api/admin/policies/route.ts
 * const h = createIamAdminHandlers(engine, {
 *   authorize: (req) => isAdminToken(req),
 *   onAdminMutation: (e) => auditLog.write(e),
 * })
 * export const GET = h.listPolicies
 * export const PUT = h.savePolicy
 * ```
 * @example
 * Rate limiting is out of scope; compose it in middleware (pseudocode):
 * ```ts
 * // middleware.ts
 * export const middleware = async (req: Request) => {
 *   if (req.nextUrl.pathname.startsWith('/api/admin/')) {
 *     const blocked = await adminRateLimit(req)
 *     if (blocked) return blocked
 *   }
 * }
 * ```
 */
export function createIamAdminHandlers<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: IamEngine<TAction, TResource, TRole, TScope>, opts: IamNext.IAdminOptions) {
  if (!opts || typeof opts.authorize !== 'function') {
    throw new Error('[@gentleduck/iam:next] createIamAdminHandlers requires an `authorize` callback.')
  }
  const { authorize, onAdminMutation, getMutationActor, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } =
    opts
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)
  const onUnauthorized = opts.onUnauthorized ?? (() => Response.json({ error: 'Unauthorized' }, { status: 401 }))
  const onError = opts.onError ?? (() => Response.json({ error: 'Internal server error' }, { status: 500 }))

  /**
   * Read gate: the same CSRF and `authorize` phase as {@link mutate}, with no audit event.
   * NOTE: CSRF runs on reads too, so an operator's `csrfCheck` is enforced alike on all four adapters.
   */
  const gate =
    <P>(fn: (req: Request, ctx: { params: Promise<P> | P }) => Promise<Response>) =>
    async (req: Request, ctx: { params: Promise<P> | P }): Promise<Response> => {
      const authz = await iamRunAdminAuthz(req, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') {
        return Response.json({ error: 'Forbidden (CSRF check failed)' }, { status: 403 })
      }
      if (authz.phase === 'unauthorized') return onUnauthorized(req)
      if (authz.phase === 'error') return onError(authz.error, req)
      try {
        return await fn(req, ctx)
      } catch (err) {
        return onError(err instanceof Error ? err : new Error(String(err)), req)
      }
    }

  /** Mutation gate: the CSRF and `authorize` phase, then an `onAdminMutation` event on success or failure. */
  const mutate =
    <P>(
      action: IamAdminAudit.Action,
      target: IamAdminAudit.Target,
      getTargetId: ((req: Request, params: P) => string | undefined) | undefined,
      fn: (
        req: Request,
        ctx: { params: Promise<P> | P },
        setTargetId: (id: string | undefined) => void,
        who: { actor?: string },
      ) => Promise<Response>,
    ) =>
    async (req: Request, ctx: { params: Promise<P> | P }): Promise<Response> => {
      // Shared CSRF + authorize phase.
      const authz = await iamRunAdminAuthz(req, effectiveCsrfCheck, authorize)
      if (authz.phase === 'forbidden') return Response.json({ error: 'Forbidden (CSRF check failed)' }, { status: 403 })
      if (authz.phase === 'unauthorized') return onUnauthorized(req)
      if (authz.phase === 'error') return onError(authz.error, req)
      let resolvedParams: P | undefined
      try {
        resolvedParams = (ctx.params instanceof Promise ? await ctx.params : ctx.params) as P
      } catch (err) {
        return onError(err instanceof Error ? err : new Error(String(err)), req)
      }
      let path = ''
      try {
        path = new URL(req.url).pathname
      } catch {
        path = req.url
      }
      // NOTE: mutable and read in `finally`, so a handler can set `targetId` once it has parsed the body
      // (`savePolicy` and `saveRole` carry the id there, not in the path).
      const auditCtx = {
        actor: authz.actor,
        action,
        target,
        targetId: resolvedParams !== undefined ? getTargetId?.(req, resolvedParams) : undefined,
        method: req.method,
        path,
        onAdminMutation,
        redactPath,
        onAuditHookError,
        includeErrorMessage,
      }
      try {
        return await iamWithAdminAudit(auditCtx, () =>
          fn(
            req,
            { params: resolvedParams as P },
            (id) => {
              auditCtx.targetId = id
            },
            iamAdminActorOptions(authz.actor, getMutationActor),
          ),
        )
      } catch (err) {
        // A body the validator rejected is the caller's mistake, not ours.
        if (iamIsValidationError(err)) {
          return Response.json({ error: `Invalid ${err.kind}`, issues: err.issues }, { status: 400 })
        }
        return onError(err instanceof Error ? err : new Error(String(err)), req)
      }
    }

  return {
    listPolicies: gate(async () => Response.json(await engine.admin.listPolicies())),
    listRoles: gate(async () => Response.json(await engine.admin.listRoles())),
    savePolicy: mutate<Record<string, string>>('replace', 'policy', undefined, async (req, _ctx, setTargetId, who) => {
      const body = (await iamReadJsonBody(() => req.json())) as AccessControl.IPolicy<TAction, TResource, TRole>
      setTargetId(iamAuditIdOf(body))
      await engine.admin.savePolicy(body, who)
      return Response.json({ ok: true })
    }),
    saveRole: mutate<Record<string, string>>('replace', 'role', undefined, async (req, _ctx, setTargetId, who) => {
      const body = (await iamReadJsonBody(() => req.json())) as AccessControl.IRole<TAction, TResource, TRole, TScope>
      setTargetId(iamAuditIdOf(body))
      await engine.admin.saveRole(body, who)
      return Response.json({ ok: true })
    }),
    assignRole: mutate<{ id: string }>(
      'create',
      'role-assignment',
      (_req, params) => params.id,
      async (req, ctx, _setTargetId, who) => {
        // Validated at the edge, like the other adapters, so the refusal does not depend on the storage adapter.
        const params = ctx.params instanceof Promise ? await ctx.params : ctx.params
        const body: unknown = await iamReadJsonBody(() => req.json())
        const scope = iamOptionalStringField(body, 'scope')
        await engine.admin.assignRole(
          iamRequirePathParam(params?.id, 'id'),
          iamAsRoleLiteral<TRole>(iamRequireStringField(body, 'roleId')),
          scope === undefined ? undefined : iamAsScopeLiteral<TScope>(scope),
          who,
        )
        return Response.json({ ok: true })
      },
    ),
    revokeRole: mutate<{ id: string; roleId: string }>(
      'delete',
      'role-assignment',
      (_req, params) => params.id,
      async (_req, ctx, _setTargetId, who) => {
        const params = ctx.params instanceof Promise ? await ctx.params : ctx.params
        await engine.admin.revokeRole(
          iamRequirePathParam(params?.id, 'id'),
          iamAsRoleLiteral<TRole>(iamRequirePathParam(params?.roleId, 'roleId')),
          undefined,
          who,
        )
        return Response.json({ ok: true })
      },
    ),
  }
}
