/**
 * Next.js App Router server-side integration.
 *
 * Covers:
 *   - API route wrappers (Route Handlers)
 *   - Server Component helpers
 *   - Next.js Middleware integration
 *   - Permission map generation for client hydration
 */

import type { IamEngine } from '../../core'
import type { AccessControl, IamClient, IamRequest } from '../../core/types'
import { iamIsValidationError } from '../../shared/errors'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'
import {
  type IamAdminAudit,
  iamActionForMethod,
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
type RouteContext = { params: Promise<Record<string, string>> | Record<string, string> }
/** Next.js App Router route handler signature. */
type RouteHandler = (req: Request, ctx: RouteContext) => Promise<Response>

/** Next.js server integration types. Type-only namespace - zero bundle cost. */
export namespace IamNext {
  /**
   * Describes options for {@link withIamAccess}.
   *
   * Every extractor has a sensible default.
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
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, req: Request) => Response
  }

  /**
   * Describes options for {@link createIamNextMiddleware}.
   *
   * `rules` and `getUserId` are required.
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
    /**
     * Handles a denied request (defaults to 403 JSON).
     *
     * The other four integrations have always had this; this one did not, so an
     * operator porting a `onDenied` override here silently lost it.
     */
    onDenied?: (req: Request) => Response
    /** Handles a request with no user (defaults to 401 JSON). */
    onUnauthorized?: (req: Request) => Response
    /** Handles thrown errors during evaluation (defaults to 500 JSON). */
    onError?: (err: Error, req: Request) => Response
  }

  /**
   * Required guard callback for admin Route Handlers.
   *
   * Same threat model as the Express `adminRouter`: any handler that writes
   * policies or roles must be gated.
   */
  export type IAdminAuthorize = (req: Request) => boolean | Promise<boolean>

  /** Describes options for {@link createIamAdminHandlers}. `authorize` is required. */
  export interface IAdminOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin handler (read or write). */
    authorize: IAdminAuthorize
    /** Overrides the 401 unauthorized response. */
    onUnauthorized?: (req: Request) => Response
    /** Overrides the 500 internal error response. */
    onError?: (err: Error, req: Request) => Response
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
 * Wraps a Next.js App Router route handler with an access check.
 *
 * Returns 401 when no user is present, 403 when denied, and otherwise invokes
 * the wrapped handler.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param action - Specifies the action being performed.
 * @param resourceType - Specifies the resource type required for the check.
 * @param handler - Provides the downstream route handler invoked on allow.
 * @param opts - Configures optional extractors and `scope` override.
 * @returns A wrapped route handler.
 * `opts.getUserId` is required - identity is never derived from request
 * headers, because a header is caller-controlled. Wire it to your session.
 *
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
  } = opts

  return async (req, ctx) => {
    try {
      // Inside the try, like every other extractor: a throwing `getUserId` must
      // reach `onError` rather than the framework's boundary.
      const userId = await getUserId(req)
      if (!iamIsSubjectId(userId)) {
        return Response.json({ error: 'Unauthorized' }, { status: 401 })
      }

      const params = ctx.params instanceof Promise ? await ctx.params : ctx.params
      const resourceId = params?.id

      const allowed = await engine.can(
        userId,
        action,
        { type: resourceType, id: resourceId, attributes: {} },
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
 * Returns whether `subjectId` can perform `(action, resourceType)`.
 *
 * Designed for use inside Server Components or server actions.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param subjectId - Identifies the subject performing the action.
 * @param action - Specifies the action being performed.
 * @param resourceType - Specifies the resource type required for the check.
 * @param resourceId - Optional resource instance ID.
 * @param scope - Optional scope constraint.
 * @returns Resolves to `true` when allowed and `false` otherwise.
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
): Promise<boolean> {
  return engine.can(
    subjectId,
    action,
    {
      type: resourceType,
      id: resourceId,
      attributes: {},
    },
    undefined,
    scope,
  )
}

/**
 * Builds a {@link IamClient.PermissionMap} for a Server Component or layout.
 *
 * Pass the result to the React `AccessProvider` on the client side.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @template TMode - Engine mode; determines whether the map is typed or plain
 *   booleans. Inferred from `engine`, so a development-mode engine still
 *   returns a typed {@link IamClient.PermissionMap} and a production one
 *   returns `Record<string, boolean>` - what `engine.permissions` itself
 *   returns in each mode. Before the default flipped to `'production'` this
 *   helper was implicitly development-only and would not accept a production
 *   engine at all.
 * @param engine - Provides the access engine to consult.
 * @param subjectId - Identifies the subject whose permissions are computed.
 * @param checks - Lists the permission tuples to evaluate.
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
): Promise<AccessControl.ModePermissionMap<TMode, TAction, TResource, TScope>> {
  return engine.permissions(subjectId, checks)
}

/**
 * Builds a Next.js Edge Middleware matcher that protects routes by a list of
 * pattern-keyed rules.
 *
 * Returns `null` when the request passes or no rule matches; otherwise returns
 * a `Response` (401/403/500).
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
  // This was the one integration that passed no environment at all, so a rule
  // keyed on `environment.ip` / `.userAgent` / `.hour` never fired here while
  // firing in express, hono, nest and next's own `withIamAccess` on the same
  // request. Same default as `withIamAccess`.
  const {
    getEnvironment = (req: Request) =>
      iamExtractEnvironment({ headers: req.headers, method: req.method, url: req.url }),
    onDenied = () => Response.json({ error: 'Forbidden' }, { status: 403 }),
    onUnauthorized = () => Response.json({ error: 'Unauthorized' }, { status: 401 }),
    onError = () => Response.json({ error: 'Internal server error' }, { status: 500 }),
  } = opts

  return async (req: Request): Promise<Response | null> => {
    const url = new URL(req.url)
    // Refused before canonicalisation, not after. `/admin/..%2fpublic` keeps
    // its `%2f` through `new URL()`, so this middleware decoded it, resolved
    // the `..`, matched the `/public` rule and allowed - while next's own
    // router decoded the same escape into a path segment and served `/admin`.
    // Authorized as one resource, served as another; the same refusal
    // `iamDefaultResource` gives express and hono.
    if (iamPathIsAmbiguous(url.pathname)) {
      return onDenied(req)
    }
    // `//admin` and `/%61dmin` both survive `new URL()` and skip a `/admin`
    // rule while still routing to `/admin`. Match on the canonical form.
    const path = iamNormalizePathname(url.pathname)

    // `iamNormalizePathname` decodes exactly once; the residue check that makes
    // that safe lives in `iamDefaultResource`, and this call site did not
    // reproduce it. A path the framework may decode a second time either picked
    // the wrong rule (`/posts/%252e%252e/admin` was checked as `posts` while
    // routing to `/admin`) or matched none - and no rule means `return null`,
    // which passes the request through with no authorization call at all.
    // Refused here, as `IAM_UNKNOWN_RESOURCE` refuses it in express and hono.
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
      // Inside the try, like the other four: a throwing `getUserId` reaches
      // `onError` rather than escaping to the framework's own boundary, where
      // it would be reported as an application error rather than an authz one.
      const userId = await opts.getUserId(req)
      if (!iamIsSubjectId(userId)) {
        return onUnauthorized(req)
      }

      // `TAction` is erased at runtime, so an inferred method action cannot be
      // narrowed to it. One documented widening rather than one per branch.
      const action: TAction = matchedRule.action ?? (iamActionForMethod(req.method) as TAction)

      const allowed = await engine.can(
        userId,
        action,
        {
          type: matchedRule.resource,
          attributes: {},
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
 * Builds pre-bound admin Route Handlers for Next.js App Router.
 *
 * Every handler runs `authorize(req)` first; failure replies 401. Throws at
 * construction time when `opts.authorize` is missing.
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
 * Rate limiting is out of scope; compose at the framework layer with the
 * caller's middleware of choice. Pseudocode:
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
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)
  const onUnauthorized = opts.onUnauthorized ?? (() => Response.json({ error: 'Unauthorized' }, { status: 401 }))
  const onError = opts.onError ?? (() => Response.json({ error: 'Internal server error' }, { status: 500 }))

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

  /**
   * Mutation gate: unlike {@link gate} it runs the CSRF check first, then emits
   * an `onAdminMutation` audit event whether the handler resolves or rejects.
   */
  const mutate =
    <P>(
      action: IamAdminAudit.Action,
      target: IamAdminAudit.Target,
      getTargetId: ((req: Request, params: P) => string | undefined) | undefined,
      fn: (
        req: Request,
        ctx: { params: Promise<P> | P },
        setTargetId: (id: string | undefined) => void,
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
      // Mutable, and read by `iamWithAdminAudit` in its `finally` rather than at
      // call time. `getTargetId` only sees the request, which is enough for a
      // role assignment and useless for `PUT /policies`, where the id is in a
      // body nobody has parsed yet - so that event recorded that *a* policy had
      // been replaced without saying which one.
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
          fn(req, { params: resolvedParams as P }, (id) => {
            auditCtx.targetId = id
          }),
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
    savePolicy: mutate<Record<string, string>>('replace', 'policy', undefined, async (req, _ctx, setTargetId) => {
      const body = (await iamReadJsonBody(() => req.json())) as AccessControl.IPolicy<TAction, TResource, TRole>
      setTargetId(iamAuditIdOf(body))
      await engine.admin.savePolicy(body)
      return Response.json({ ok: true })
    }),
    saveRole: mutate<Record<string, string>>('replace', 'role', undefined, async (req, _ctx, setTargetId) => {
      const body = (await iamReadJsonBody(() => req.json())) as AccessControl.IRole<TAction, TResource, TRole, TScope>
      setTargetId(iamAuditIdOf(body))
      await engine.admin.saveRole(body)
      return Response.json({ ok: true })
    }),
    assignRole: mutate<{ id: string }>(
      'create',
      'role-assignment',
      (_req, params) => params.id,
      async (req, ctx) => {
        // Validated at the edge, the way express and hono do. This used to read
        // the body through one cast and the path param through another and hand
        // all three straight to `engine.admin.assignRole`: `{"roleId": 7}`, an
        // array body, a missing `:id` and an empty `:id` all reached the engine.
        // No bad grant landed - the engine refuses each one by name - but the
        // refusal was entirely delegated, so a consumer with a custom adapter
        // that does not repeat those checks lost it on two of four integrations.
        const params = ctx.params instanceof Promise ? await ctx.params : ctx.params
        const body: unknown = await iamReadJsonBody(() => req.json())
        const scope = iamOptionalStringField(body, 'scope')
        await engine.admin.assignRole(
          iamRequirePathParam(params?.id, 'id'),
          iamAsRoleLiteral<TRole>(iamRequireStringField(body, 'roleId')),
          scope === undefined ? undefined : iamAsScopeLiteral<TScope>(scope),
        )
        return Response.json({ ok: true })
      },
    ),
    revokeRole: mutate<{ id: string; roleId: string }>(
      'delete',
      'role-assignment',
      (_req, params) => params.id,
      async (_req, ctx) => {
        const params = ctx.params instanceof Promise ? await ctx.params : ctx.params
        await engine.admin.revokeRole(
          iamRequirePathParam(params?.id, 'id'),
          iamAsRoleLiteral<TRole>(iamRequirePathParam(params?.roleId, 'roleId')),
        )
        return Response.json({ ok: true })
      },
    ),
  }
}
