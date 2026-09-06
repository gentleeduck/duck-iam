import type { IamEngine } from '../../core'
import type { AccessControl, IamPrimitives, IamRequest } from '../../core/types'
import { iamIsValidationError } from '../../shared/errors'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'
import {
  IAM_UNKNOWN_RESOURCE,
  type IamAdminAudit,
  iamActionForMethod,
  iamAuditIdOf,
  iamDefaultCsrfCheck,
  iamDefaultResource,
  iamExtractEnvironment,
  iamIsSubjectId,
  iamNoticeCsrfDefaultIfNeeded,
  iamOptionalStringField,
  iamPathIsAmbiguous,
  iamRequirePathParam,
  iamRequireStringField,
  iamRunAdminAuthz,
  iamWithAdminAudit,
} from '../generic'

// Reflect.defineMetadata/getMetadata come from reflect-metadata (used by NestJS)
declare namespace Reflect {
  function defineMetadata(key: string, value: unknown, target: object): void
  function getMetadata(key: string, target: object): unknown
  // Not from reflect-metadata - this is the ES2015 built-in, redeclared here
  // only because the namespace above shadows the global one for this file.
  // The rest of the package reads unknown properties through it.
  function get(target: object, key: string): unknown
}

// NestJS is a peer dep; these are the minimum shapes the guard touches.

/** Minimal NestJS request shape. */
export interface NestRequest {
  user?: { id?: string; sub?: string; [key: string]: unknown }
  params?: Record<string, string>
  method: string
  path?: string
  route?: { path?: string }
  headers?: Record<string, string | string[] | undefined>
  ip?: string
  /** Populated by auth middleware (e.g. duck-auth). */
  session?: { identityId?: string; id?: string; [key: string]: unknown }
  /** Populated by auth middleware (e.g. duck-auth). */
  identity?: { id?: string; [key: string]: unknown } | null
  [key: string]: unknown
}

/** Minimal NestJS execution context. */
interface NestExecutionContext {
  switchToHttp(): { getRequest(): NestRequest }
  // NestJS returns Function; we use `object` as the compatible supertype.
  getHandler(): object
}

/** Metadata key for the @IamAuthorize decorator. */
export const IAM_ACCESS_METADATA_KEY = 'duck-iam:authorize'

/** NestJS server integration types. Type-only namespace - zero bundle cost. */
export namespace IamNest {
  /**
   * Describes the metadata payload attached by the {@link IamAuthorize} decorator.
   *
   * @template TAction - Constrains valid action strings.
   * @template TResource - Constrains valid resource strings.
   * @template TScope - Constrains valid scope strings.
   */
  export interface IAuthorizeMeta<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    /** Specifies the required action (e.g. `'delete'`, `'manage'`). */
    action?: TAction
    /** Specifies the target resource type (e.g. `'post'`, `'user'`). */
    resource?: TResource
    /** Optional scope constraint applied to the check. */
    scope?: TScope
    /** When `true`, infers action from HTTP method and resource from route path. */
    infer?: boolean
  }

  /**
   * Describes options for {@link iamNestAccessGuard}.
   *
   * Each extractor has a sensible default.
   *
   * @template TScope - Constrains valid scope strings.
   */
  export interface IGuardOptions<TScope extends string = string> {
    /** Extracts the current user ID from the request. */
    getUserId?: (request: NestRequest) => string | null
    /** Extracts environment context (IP, user-agent, etc.) from the request. */
    getEnvironment?: (request: NestRequest) => IamRequest.IEnvironment
    /** Extracts the resource ID from the request. */
    getResourceId?: (request: NestRequest) => string | undefined
    /** Determines the scope used for the access check. */
    getScope?: (request: NestRequest) => TScope | undefined
    /** Extracts extra attributes to attach to `resource.attributes` for this check
     *  (e.g. an owning user id, a computed flag) -- merged in before `engine.can()`.
     *  Receives the resolved action/resource/scope, since the right attributes
     *  depend on which resource and scope this check runs against (a `users` row
     *  IS its own subject; an `iamAssignments` row's subject lives in a column).
     *  Values must be `AttributeValue` -- use `null` for "absent", not `undefined`. */
    getResourceAttributes?: (
      request: NestRequest,
      ctx: { action: string; resource: string; scope: TScope | undefined },
    ) => Readonly<IamPrimitives.Attributes> | Promise<Readonly<IamPrimitives.Attributes>>
    /** Handles thrown errors during evaluation; return `true` to allow, `false` to deny. */
    onError?: (err: Error, request: NestRequest) => boolean
  }

  /** Required guard callback for the admin controller methods. */
  export type IAdminAuthorize = (request: NestRequest) => boolean | Promise<boolean>

  /** Describes options for {@link createIamAdminOperations}. `authorize` is required. */
  export interface IAdminOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin operation. */
    authorize: IAdminAuthorize
    /**
     * Optional audit hook fired AFTER every mutation handler (savePolicy/
     * saveRole/assignRole/revokeRole) completes - success or failure. The
     * hook is fire-and-forget: a slow or throwing implementation never
     * blocks the request and can never alter the response. `listPolicies` /
     * `listRoles` (reads) do not fire it.
     *
     * See {@link IamAdminAudit.IOptions} for additional hardening knobs:
     * `redactPath`, `onAuditHookError`, and `includeErrorMessage`.
     */
    onAdminMutation?: IamAdminAudit.Hook
    /**
     * Builds the error thrown when `authorize` refuses. Express, hono and next
     * have declared this for some time; nest did not declare it at all, so an
     * operator porting a custom unauthorized body to nest lost it with no type
     * error - the option simply was not in the interface.
     *
     * Nest signals by throwing rather than by writing a response, so this
     * returns the `Error` to throw instead of a response body. Give it a
     * `statusCode` (Nest's base filter duck-types that, not `status`) or return
     * an `HttpException` from `@nestjs/common`. Defaults to a 401.
     */
    onUnauthorized?: (request: NestRequest) => Error
    /**
     * Builds the error thrown for a CSRF refusal. Defaults to a 403.
     */
    onForbidden?: (request: NestRequest) => Error
    /**
     * Maps an internal failure - a throwing `authorize`, an engine fault - to
     * the error thrown to the framework. Defaults to a 500 whose message is the
     * fixed `'Internal server error'`, with the original attached as `cause`.
     *
     * The default is what closes two gaps. Nest used to re-throw the original
     * error untouched, so (a) every failure except 401/403 arrived at the host
     * with no status at all, where the other three answer a real code and a
     * JSON envelope, and (b) an engine error's message rode out of the adapter
     * intact - `includeErrorMessage: false` governs only the *audit* string, so
     * a driver error reading `DB password=hunter2` reached the host's filter
     * with the flag off. Express, hono and next always answer the fixed
     * `{error: 'Internal server error'}` there; nest now says the same thing.
     *
     * Return the original from a custom implementation if a host filter of
     * yours wants it - that is then a deliberate choice rather than a default.
     */
    onError?: (err: Error, request: NestRequest) => Error
  }
}

/**
 * What a handler carries, and whether it carries anything at all.
 *
 * The two are separate answers and the guard needs both. "No decorator" means
 * allow - an undecorated controller method is not this package's business.
 * "Decorated, but the metadata is not a shape we can read" means the author
 * asked for a check that cannot be run, and that must not resolve to the same
 * `true`.
 */
interface IHandlerMeta {
  /** A `__accessMeta` property or reflect entry existed, whatever its shape. */
  readonly present: boolean
  /** The metadata, when it is actually usable. */
  readonly meta: IamNest.IAuthorizeMeta | undefined
}

/**
 * Is this a usable {@link IamNest.IAuthorizeMeta}?
 *
 * Every field is optional, so the check is "nothing present has the wrong
 * type" rather than "these keys exist". That is deliberately permissive about
 * *extra* keys - a caller adding their own annotation to the object should not
 * be refused - and strict about the four the guard actually reads, because each
 * one steers a different part of the decision: `infer` picks between the route
 * and the literals, `action` and `resource` are what `engine.can` is asked
 * about, and `scope` decides which tenant the answer is for.
 *
 * This used to be two casts. `__accessMeta` is a plain property on a function
 * object and `Reflect.getMetadata` returns `any`, so nothing had ever checked
 * either one; a `scope` that arrived as a number was handed to `engine.can` as
 * a scope, and the guard's own `if (!meta) return true` turned a falsy value
 * into a pass.
 *
 * @param value - The raw property or reflect entry.
 * @returns Whether the guard can read it.
 */
function isAuthorizeMeta(value: unknown): value is IamNest.IAuthorizeMeta {
  if (value === null || typeof value !== 'object') return false
  const action = Reflect.get(value, 'action')
  const resource = Reflect.get(value, 'resource')
  const scope = Reflect.get(value, 'scope')
  const infer = Reflect.get(value, 'infer')
  if (action !== undefined && typeof action !== 'string') return false
  if (resource !== undefined && typeof resource !== 'string') return false
  if (scope !== undefined && typeof scope !== 'string') return false
  if (infer !== undefined && typeof infer !== 'boolean') return false
  return true
}

/**
 * Marks a controller method with access requirements.
 *
 * Stores metadata via `reflect-metadata` when available and also attaches
 * `__accessMeta` so the guard works without that package.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TScope - Constrains valid scope strings.
 * @param meta - Configures the access metadata; defaults to `{ infer: true }`.
 * @returns A NestJS `MethodDecorator`.
 */
export function IamAuthorize<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  meta: IamNest.IAuthorizeMeta<TAction, TResource, TScope> = { infer: true } as IamNest.IAuthorizeMeta<
    TAction,
    TResource,
    TScope
  >,
): MethodDecorator {
  return (_target, _propertyKey, descriptor) => {
    if (Reflect?.defineMetadata) {
      Reflect.defineMetadata(IAM_ACCESS_METADATA_KEY, meta, descriptor.value as object)
    }
    if (descriptor.value != null) {
      Object.defineProperty(descriptor.value, '__accessMeta', { value: meta, configurable: true, writable: true })
    }
    return descriptor
  }
}

/**
 * Extract authorize metadata from a handler, and say whether there was any.
 *
 * @param handler - The controller method Nest resolved for this request.
 * @returns Presence and, when readable, the metadata.
 */
function getHandlerMeta(handler: object): IHandlerMeta {
  const raw: unknown =
    '__accessMeta' in handler
      ? Reflect.get(handler, '__accessMeta')
      : Reflect?.getMetadata
        ? Reflect.getMetadata(IAM_ACCESS_METADATA_KEY, handler)
        : undefined
  // `undefined` is indistinguishable from absent and is what an unset
  // reflect key answers, so it counts as "no decorator". Every other value -
  // `null`, `0`, `''`, a string, an array - means something was attached.
  if (raw === undefined) return { meta: undefined, present: false }
  return { meta: isAuthorizeMeta(raw) ? raw : undefined, present: true }
}

/**
 * Builds a NestJS `canActivate` function that reads {@link IamAuthorize} metadata
 * off the handler and runs `engine.can(...)`.
 *
 * Handlers without metadata pass through (allow).
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param opts - Configures optional extractors and error handler.
 * @returns A function suitable as a NestJS guard's `canActivate` body.
 * @example
 * ```ts
 * @Injectable()
 * class AccessGuard implements CanActivate {
 *   canActivate = iamNestAccessGuard(engine)
 * }
 * ```
 */
export function iamNestAccessGuard<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: IamEngine<TAction, TResource, TRole, TScope>, opts: IamNest.IGuardOptions<TScope> = {}) {
  const {
    getUserId = (req: NestRequest) => (req.user?.id as string) ?? (req.user?.sub as string) ?? null,
    getEnvironment = (req: NestRequest) => iamExtractEnvironment(req),
    getResourceId = (req: NestRequest) => req.params?.id,
    getResourceAttributes,
    getScope,
    onError = () => false,
  } = opts

  return async (context: NestExecutionContext): Promise<boolean> => {
    const request = context.switchToHttp().getRequest()
    const handler = context.getHandler()

    const { meta, present } = getHandlerMeta(handler)

    if (!present) return true // No @IamAuthorize decorator: allow.
    if (meta === undefined) {
      // Decorated, but with something the guard cannot read. This used to take
      // the branch above and allow: `if (!meta) return true` cannot tell "no
      // decorator" from "decorator carrying `null`", and the same line let a
      // `__accessMeta` inherited off a prototype decide the request. A check
      // that was asked for and cannot be run is a denial, routed through
      // `onError` so an operator sees which handler is broken rather than
      // hunting a silent 403.
      return onError(
        new Error(
          '[@gentleduck/iam:nest] handler carries @IamAuthorize metadata that is not readable ' +
            '(expected an object with optional string action/resource/scope and boolean infer); denying.',
        ),
        request,
      )
    }

    try {
      // Inside the try, like every other extractor: a throwing `getUserId` must
      // reach `onError` rather than the framework's boundary.
      const userId = getUserId(request)
      if (!iamIsSubjectId(userId)) return false

      const action = meta.infer ? iamActionForMethod(request.method) : (meta.action ?? 'read')
      const resource = meta.infer ? inferResource(request) : (meta.resource ?? 'unknown')
      const scope = (meta.scope as TScope | undefined) ?? getScope?.(request)

      const attributes = getResourceAttributes ? await getResourceAttributes(request, { action, resource, scope }) : {}
      return await engine.can(
        userId,
        action as TAction,
        { type: resource as TResource, id: getResourceId(request), attributes },
        getEnvironment(request),
        scope,
      )
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), request)
    }
  }
}

/**
 * Infer resource type from the request route path, agreeing with the shared
 * {@link iamDefaultResource} that express, hono and next use.
 *
 * Three things used to make Nest disagree with it, so a policy written against
 * one framework silently did not apply in the other:
 *
 * - the *last* segment was taken rather than the first, so on any platform with
 *   no `request.route` - `@nestjs/platform-fastify` exposes `routeOptions.url` /
 *   `routerPath` and sets no `route` - `/posts/42` authorized against `42`;
 * - the `%`-after-one-decode guard was applied to that one segment instead of
 *   every segment, so `/admin/%252e%252e/posts` came back as a confident
 *   `posts` while express and hono denied it as `unknown`;
 * - a `*` segment was returned verbatim, and `'*'` is the engine's wildcard
 *   *pattern* sentinel: a `@Get('*')` route authorized as `'*'` matched every
 *   `resources: ['*']` allow and no targeted deny.
 *
 * The raw-path branch is now the shared helper outright. The template branch
 * keeps its own reading - the template is the router's own string and needs no
 * canonicalisation - but takes the first non-param segment, so both branches
 * name the same resource, and treats any non-literal segment the way the helper
 * treats an untrustworthy path.
 */
function inferResource(request: NestRequest): string {
  // Checked before the template branch, because a matched template does not
  // make an ambiguous target safe - it only records which route express picked
  // for it. Express matched `/public/*` for `/public/../admin` and this
  // returned a confident `public`, so the request was authorized as public and
  // then served by the public handler on nest while hono and next served
  // `/admin`. A target no two routers resolve alike names no resource.
  if (typeof request.path === 'string' && iamPathIsAmbiguous(request.path)) return IAM_UNKNOWN_RESOURCE
  const template: string | undefined = request.route?.path
  if (typeof template !== 'string') return iamDefaultResource(request.path).type

  const first = template
    .split('/')
    .filter((segment: string) => segment.length > 0)
    .find((segment: string) => !segment.startsWith(':'))
  if (first === undefined) return 'root'
  return first.includes('%') || first.includes('*') ? IAM_UNKNOWN_RESOURCE : first
}

/** DI token for the access Engine in NestJS. */
export const IAM_ACCESS_ENGINE_TOKEN = 'ACCESS_ENGINE'

/**
 * Builds a NestJS provider descriptor bound to {@link IAM_ACCESS_ENGINE_TOKEN}.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param factory - Provides the sync or async engine factory.
 * @returns A `{ provide, useFactory }` descriptor for NestJS DI.
 */
export function createIamEngineProvider<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(factory: () => IamEngine<TAction, TResource, TRole, TScope> | Promise<IamEngine<TAction, TResource, TRole, TScope>>) {
  return {
    provide: IAM_ACCESS_ENGINE_TOKEN,
    useFactory: factory,
  }
}

/**
 * Error carrying both `status` and `statusCode`.
 *
 * Nest's base exception filter routes anything that is not an `HttpException`
 * to `handleUnknownError`, whose only non-500 branch duck-types
 * `err.statusCode && err.message` - `statusCode`, not `status`. With `status`
 * alone every unauthenticated poke at an admin endpoint got a 500 plus an
 * error-level stack trace in the log, where express, hono and next all return
 * a real 401/403. `status` is kept for express-style consumers.
 */
function adminHttpError(message: string, statusCode: number): Error {
  return Object.assign(new Error(message), { status: statusCode, statusCode })
}

/**
 * Builds framework-agnostic admin operations for use inside a NestJS controller.
 *
 * NestJS's decorator-driven routing means we do not ship a router factory;
 * instead this returns a record of admin handlers the user wires into their
 * `@Controller` methods. Enforces `authorize` at construction time so the
 * controller cannot be instantiated unguarded.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine whose `admin` operations are exposed.
 * @param opts - Must include `authorize`.
 * @returns A record of `(req, ...args) => Promise` admin handlers.
 * @throws Error when `opts.authorize` is not a function.
 * @example
 * ```ts
 * @Controller('admin')
 * class IamAdminController {
 *   private h = createIamAdminOperations(engine, {
 *     authorize: (req) => isAdmin(req.user),
 *     onAdminMutation: (e) => auditLog.write(e),
 *   })
 *   @Get('policies') listPolicies(@Req() req) { return this.h.listPolicies(req) }
 * }
 * ```
 * @example
 * Rate limiting is out of scope; compose with NestJS's `@nestjs/throttler` or a
 * global guard. Pseudocode:
 * ```ts
 * @UseGuards(ThrottlerGuard)
 * @Throttle({ default: { limit: 30, ttl: 60_000 } })
 * @Controller('admin') class IamAdminController { ... }
 * ```
 */
export function createIamAdminOperations<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: IamEngine<TAction, TResource, TRole, TScope>, opts: IamNest.IAdminOptions) {
  if (!opts || typeof opts.authorize !== 'function') {
    throw new Error('[@gentleduck/iam:nest] createIamAdminOperations requires an `authorize` callback.')
  }
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)

  const onUnauthorized = opts.onUnauthorized ?? (() => adminHttpError('Unauthorized', 401))
  const onForbidden = opts.onForbidden ?? (() => adminHttpError('Forbidden (CSRF check failed)', 403))
  // The original is attached as `cause`, so nothing is lost to a logger that
  // walks the chain - only to the response, which is the point.
  const onError =
    opts.onError ?? ((err: Error) => Object.assign(adminHttpError('Internal server error', 500), { cause: err }))

  /**
   * A body the validator rejected is the caller's mistake, and `400` is what
   * express and hono answer for it. `IamValidationError.kind` and `.issues` are
   * this package's own strings describing the caller's own document, so they
   * are safe to return - unlike an internal error message, which is what
   * `onError` exists to keep in.
   */
  const asThrowable = (err: unknown, req: NestRequest): Error => {
    if (iamIsValidationError(err)) {
      return Object.assign(adminHttpError(`Invalid ${err.kind}`, 400), { cause: err, issues: err.issues })
    }
    return onError(err instanceof Error ? err : new Error(String(err)), req)
  }

  /**
   * Gate that returns whatever {@link IamNest.IAdminAuthorize} returned so the
   * value can be forwarded into the audit event as `actor`. Throws a 403 (CSRF)
   * or 401 (denied) via {@link adminHttpError}.
   *
   * Delegates to the shared {@link iamRunAdminAuthz}, which express, hono and
   * next already used. The hand-rolled version this replaces was the same two
   * checks in the same order, and differed in the two places the shared gate
   * exists for:
   *
   * - it returned `authorize`'s raw answer as the audit `actor`, so the
   *   documented `authorize: (req) => req.user?.role === 'admin'` wrote
   *   `actor: true` into the admin audit trail where the other three write
   *   `undefined` and warn the operator once. `iamIsNameableActor` exists
   *   precisely to keep a boolean out of the field that is supposed to say who
   *   made the change, and nest was the one adapter that did not consult it;
   * - a `csrfCheck` that *threw* propagated out raw, where the shared gate
   *   reads "cannot answer" as "has not said yes" and returns `forbidden`. A
   *   predicate that throws is a broken predicate, and it must not be the
   *   difference between a 403 and a 500 with a stack trace.
   *
   * `phase: 'error'` - a throwing `authorize` - keeps nest's existing shape: it
   * is re-thrown, so the controller's own filter sees the original error rather
   * than a 401 that would blame the caller for a server fault.
   */
  const gateWithActor = async (req: NestRequest): Promise<unknown> => {
    // CSRF guard runs before authorize so a cookie-based authorize cannot
    // be tricked by a cross-origin POST. No-op when csrfCheck is omitted.
    const authz = await iamRunAdminAuthz(req, effectiveCsrfCheck, authorize)
    if (authz.phase === 'forbidden') throw onForbidden(req)
    if (authz.phase === 'unauthorized') throw onUnauthorized(req)
    // A throwing `authorize` is a server fault, not the caller's - and it used
    // to escape raw, carrying its message and no status. `onError` gives it
    // both, and the original stays reachable as `cause`.
    if (authz.phase === 'error') throw onError(authz.error, req)
    return authz.actor
  }

  /**
   * Run a mutation, firing `onAdminMutation` in a finally block so the
   * audit event lands even when the handler throws.
   */
  const runMutation = async <T>(
    req: NestRequest,
    action: IamAdminAudit.Action,
    target: IamAdminAudit.Target,
    targetId: string | undefined,
    handler: () => Promise<T>,
  ): Promise<T> => {
    // IamAuthorize denial or throw - do NOT emit audit (mutation never started).
    const actor = await gateWithActor(req)
    // Shared audit wrapper.
    try {
      return await iamWithAdminAudit(
        {
          actor,
          action,
          target,
          targetId,
          method: req.method,
          path: req.route?.path ?? req.path ?? '',
          onAdminMutation,
          redactPath,
          onAuditHookError,
          includeErrorMessage,
        },
        handler,
      )
    } catch (err) {
      // Inside the audit wrapper's own try, so the event still fires with
      // `success: false` - `asThrowable` only decides what the *framework*
      // sees. Before this, a validation failure and an engine fault both left
      // here as whatever was thrown, with no status, and express and hono
      // answered 400 and 500 for the same two.
      throw asThrowable(err, req)
    }
  }

  /**
   * Read gate. Runs the same CSRF + `authorize` phase as a mutation and emits
   * no audit event. Express, hono and next now do the same - nest was the only
   * adapter CSRF-checking reads, and the four agree rather than three changing
   * to match the looser one.
   */
  const gate = async (req: NestRequest): Promise<void> => {
    await gateWithActor(req)
  }

  return {
    async listPolicies(req: NestRequest) {
      await gate(req)
      return engine.admin.listPolicies()
    },
    async listRoles(req: NestRequest) {
      await gate(req)
      return engine.admin.listRoles()
    },
    async savePolicy(req: NestRequest, body: AccessControl.IPolicy<TAction, TResource, TRole>) {
      // `iamAuditIdOf` rather than a cast: the declared parameter type is what
      // a controller *promises*, and the audit target is read off whatever JSON
      // actually arrived. A body with no usable id has no target rather than an
      // invented one. Same helper hono and next use, so the trail reads the
      // same on all three.
      return runMutation(req, 'replace', 'policy', iamAuditIdOf(body), async () => {
        await engine.admin.savePolicy(body)
        return { ok: true as const }
      })
    },
    async saveRole(req: NestRequest, body: AccessControl.IRole<TAction, TResource, TRole, TScope>) {
      return runMutation(req, 'replace', 'role', iamAuditIdOf(body), async () => {
        await engine.admin.saveRole(body)
        return { ok: true as const }
      })
    },
    /**
     * The declared parameter types are what a Nest controller *promises* to
     * pass, not what arrives. `@Param('id')` on an unmatched segment is
     * `undefined` and `@Body()` is whatever JSON was posted, so `{"roleId": 7}`,
     * `{}`, an array body and an empty `:id` all used to reach
     * `engine.admin.assignRole` unchecked. The engine refuses each of them by
     * name, so no bad grant ever landed - but that made the refusal entirely
     * the engine's, and a consumer wiring a custom adapter that does not repeat
     * those checks lost it. Express and hono validate at the edge; these now do
     * too, inside `runMutation` so a refusal is audited as the failure it is.
     */
    async assignRole(req: NestRequest, subjectId: string, body: { roleId: TRole; scope?: TScope }) {
      return runMutation(req, 'create', 'role-assignment', subjectId, async () => {
        const scope = iamOptionalStringField(body, 'scope')
        await engine.admin.assignRole(
          iamRequirePathParam(subjectId, 'id'),
          iamAsRoleLiteral<TRole>(iamRequireStringField(body, 'roleId')),
          scope === undefined ? undefined : iamAsScopeLiteral<TScope>(scope),
        )
        return { ok: true as const }
      })
    },
    async revokeRole(req: NestRequest, subjectId: string, roleId: TRole) {
      return runMutation(req, 'delete', 'role-assignment', subjectId, async () => {
        await engine.admin.revokeRole(
          iamRequirePathParam(subjectId, 'id'),
          iamAsRoleLiteral<TRole>(iamRequirePathParam(roleId, 'roleId')),
        )
        return { ok: true as const }
      })
    },
  }
}
