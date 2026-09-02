import type { IamEngine } from '../../core'
import type { AccessControl, IamPrimitives, IamRequest } from '../../core/types'
import {
  IAM_METHOD_ACTION_MAP,
  type IamAdminAudit,
  iamDefaultCsrfCheck,
  iamExtractEnvironment,
  iamNoticeCsrfDefaultIfNeeded,
  iamWithAdminAudit,
} from '../generic'

// Reflect.defineMetadata/getMetadata come from reflect-metadata (used by NestJS)
declare namespace Reflect {
  function defineMetadata(key: string, value: unknown, target: object): void
  function getMetadata(key: string, target: object): unknown
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
  }
}

/** Handler function with attached authorize metadata. */
interface HandlerWithMeta {
  __accessMeta?: IamNest.IAuthorizeMeta
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

/** Extract authorize metadata from a handler. */
function getHandlerMeta(handler: object): IamNest.IAuthorizeMeta | undefined {
  if ('__accessMeta' in handler) {
    return (handler as HandlerWithMeta).__accessMeta
  }
  if (Reflect?.getMetadata) {
    return Reflect.getMetadata(IAM_ACCESS_METADATA_KEY, handler) as IamNest.IAuthorizeMeta | undefined
  }
  return undefined
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

    const meta = getHandlerMeta(handler)

    if (!meta) return true // No @IamAuthorize decorator: allow.

    const userId = getUserId(request)
    if (!userId) return false

    const action = meta.infer ? (IAM_METHOD_ACTION_MAP[request.method] ?? 'read') : (meta.action ?? 'read')

    const resource = meta.infer ? inferResource(request) : (meta.resource ?? 'unknown')

    const scope = (meta.scope as TScope | undefined) ?? getScope?.(request)

    try {
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

/** Infer resource type from request route path. */
function inferResource(request: NestRequest): string {
  const path: string = request.route?.path ?? request.path ?? '/'
  const segments = path.split('/').filter((s: string) => s && !s.startsWith(':'))
  return segments[segments.length - 1] ?? 'root'
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
 * Builds framework-agnostic admin operations for use inside a NestJS controller.
 *
 * IamNest's decorator-driven routing means we do not ship a router factory;
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
 * Rate limiting is out of scope; compose with IamNest's `@nestjs/throttler` or a
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
    throw new Error('[@gentleduck/iam] createIamAdminOperations requires an `authorize` callback.')
  }
  const { authorize, onAdminMutation, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } = opts
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)

  /**
   * Gate that returns whatever {@link IamNest.IAdminAuthorize} returned so the value
   * can be forwarded into the audit event as `actor`. Throws an `Error` carrying
   * `status` 403 (CSRF) or 401 (denied) so the controller surfaces a Nest exception.
   */
  const gateWithActor = async (req: NestRequest): Promise<unknown> => {
    // CSRF guard runs before authorize so a cookie-based authorize cannot
    // be tricked by a cross-origin POST. No-op when csrfCheck is omitted.
    if (effectiveCsrfCheck && !effectiveCsrfCheck(req)) {
      const err = new Error('Forbidden (CSRF check failed)') as Error & { status?: number }
      err.status = 403
      throw err
    }
    const result = await authorize(req)
    if (!result) {
      const err = new Error('Unauthorized') as Error & { status?: number }
      err.status = 401
      throw err
    }
    return result
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
    return iamWithAdminAudit(
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
  }

  /** Read gate. Unlike the express/hono/next adapters this also runs the CSRF check. */
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
      return runMutation(req, 'replace', 'policy', (body as { id?: string } | undefined)?.id, async () => {
        await engine.admin.savePolicy(body)
        return { ok: true as const }
      })
    },
    async saveRole(req: NestRequest, body: AccessControl.IRole<TAction, TResource, TRole, TScope>) {
      return runMutation(req, 'replace', 'role', (body as { id?: string } | undefined)?.id, async () => {
        await engine.admin.saveRole(body)
        return { ok: true as const }
      })
    },
    async assignRole(req: NestRequest, subjectId: string, body: { roleId: TRole; scope?: TScope }) {
      return runMutation(req, 'create', 'role-assignment', subjectId, async () => {
        await engine.admin.assignRole(subjectId, body.roleId, body.scope)
        return { ok: true as const }
      })
    },
    async revokeRole(req: NestRequest, subjectId: string, roleId: TRole) {
      return runMutation(req, 'delete', 'role-assignment', subjectId, async () => {
        await engine.admin.revokeRole(subjectId, roleId)
        return { ok: true as const }
      })
    },
  }
}
