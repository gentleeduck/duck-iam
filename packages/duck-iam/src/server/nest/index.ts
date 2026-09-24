import type { IamEngine } from '../../core'
import { hasIamErrorCode } from '../../core/errors'
import type { AccessControl, IamPrimitives, IamRequest } from '../../core/types'
import {
  iamAsActionLiteral,
  iamAsResourceLiteral,
  iamAsRoleLiteral,
  iamAsScopeLiteral,
} from '../../shared/tenant-literals'
import {
  IAM_UNKNOWN_RESOURCE,
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
  // NOTE: the ES2015 built-in, not reflect-metadata; redeclared because this namespace shadows the global `Reflect`.
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
export interface NestExecutionContext {
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
   * Options for {@link iamNestAccessGuard}; every extractor has a default.
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
    /**
     * Extra `resource.attributes` merged in before `engine.can()`; receives the resolved action, resource and scope.
     * Values must be `AttributeValue`: use `null` for "absent", not `undefined`.
     */
    getResourceAttributes?: (
      request: NestRequest,
      ctx: { action: string; resource: string; resourceId: string | undefined; scope: TScope | undefined },
    ) => Readonly<IamPrimitives.Attributes> | Promise<Readonly<IamPrimitives.Attributes>>
    /** Handles thrown errors during evaluation; return `true` to allow, `false` to deny. */
    onError?: (err: Error, request: NestRequest) => boolean
  }

  /**
   * Required admin gate: a falsy answer or a throw blocks the operation, a truthy one lets it proceed.
   * Prefer returning the actor over `true`, so the audit event and the write itself record who acted; a string
   * answer also reaches `engine.admin`. See {@link IamAdminAuthzAnswer} and `getMutationActor`.
   */
  export type IAdminAuthorize = (request: NestRequest) => IamAdminAuthzAnswer | Promise<IamAdminAuthzAnswer>

  /** Describes options for {@link createIamAdminOperations}. `authorize` is required. */
  export interface IAdminOptions extends IamAdminAudit.IOptions {
    /** Required. Runs before every admin operation. */
    authorize: IAdminAuthorize
    /** Audit hook fired after every mutation (not the list reads), on success or failure; see {@link IamAdminAudit}. */
    onAdminMutation?: IamAdminAudit.Hook
    /**
     * Names the caller for `engine.admin`, which reaches the adapter's `created_by` / `updated_by`.
     * A string `authorize` answer is forwarded without this; an object one names no one until this picks the field.
     */
    getMutationActor?: (actor: IamAdminActor) => string | undefined
    /**
     * Builds the error thrown when `authorize` refuses; defaults to a 401.
     * INFO: Nest's base filter duck-types `statusCode`, not `status`: set it, or return an `HttpException`.
     */
    onUnauthorized?: (request: NestRequest) => Error
    /** Builds the error thrown for a CSRF refusal. Defaults to a 403. */
    onForbidden?: (request: NestRequest) => Error
    /**
     * Maps an internal failure (a throwing `authorize`, an engine fault) to the thrown error; defaults to a fixed 500.
     * SECURITY: the default keeps the original only as `cause`; `includeErrorMessage` covers just the audit string.
     */
    onError?: (err: Error, request: NestRequest) => Error
  }
}

/**
 * A handler's authorize metadata, and whether it carries any at all.
 * SECURITY: no decorator allows, but a decorator with unreadable metadata must not, so the two are kept apart.
 */
interface IHandlerMeta {
  /** A `__accessMeta` property or reflect entry existed, whatever its shape. */
  readonly present: boolean
  /** The metadata, when it is actually usable. */
  readonly meta: IamNest.IAuthorizeMeta | undefined
}

/**
 * Whether a raw metadata value is a readable {@link IamNest.IAuthorizeMeta}: extra keys pass, but no field the guard
 * reads (`action`, `resource`, `scope`, `infer`) may have the wrong type, since each one steers the decision.
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
 * Marks a controller method with access requirements, via `reflect-metadata` when available and always as
 * `__accessMeta`, so the guard works without that package.
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

/** Reads a handler's authorize metadata, reporting presence separately from readability. */
function getHandlerMeta(handler: object): IHandlerMeta {
  const raw: unknown =
    '__accessMeta' in handler
      ? Reflect.get(handler, '__accessMeta')
      : Reflect?.getMetadata
        ? Reflect.getMetadata(IAM_ACCESS_METADATA_KEY, handler)
        : undefined
  // Only `undefined` (what an unset reflect key answers) means "no decorator"; `null`, `0`, `''` or an array means
  // something was attached.
  if (raw === undefined) return { meta: undefined, present: false }
  return { meta: isAuthorizeMeta(raw) ? raw : undefined, present: true }
}

/**
 * Builds a NestJS `canActivate` that reads {@link IamAuthorize} metadata off the handler and runs `engine.can(...)`.
 * Handlers without metadata are allowed.
 *
 * SECURITY: a rule reading `resource.attributes.*` sees only what `getResourceAttributes` returns; without it the
 * resource is the route's type and id alone, and such a rule cannot fire.
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
      // SECURITY: decorated but unreadable is a check that cannot run. It goes to `onError` (deny by default), so the
      // operator sees why instead of a silent 403.
      return onError(
        new Error(
          '[@gentleduck/iam:nest] handler carries @IamAuthorize metadata that is not readable ' +
            '(expected an object with optional string action/resource/scope and boolean infer); denying.',
        ),
        request,
      )
    }

    try {
      // Inside the try, like every other extractor, so a throwing `getUserId` reaches `onError`.
      const userId = getUserId(request)
      if (!iamIsSubjectId(userId)) return false

      // `isAuthorizeMeta` proved these are strings, not members of the erased union, so they widen through the named
      // helpers the other adapters use.
      // SECURITY: an undeclared action falls back to the method, as `createIamNextMiddleware` does. Defaulting to
      // 'read' would let `@IamAuthorize({ resource })` on a DELETE route pass on read permission alone.
      const action = iamAsActionLiteral<TAction>(
        meta.infer || meta.action === undefined ? iamActionForMethod(request.method) : meta.action,
      )
      const resource = iamAsResourceLiteral<TResource>(
        meta.infer ? inferResource(request) : (meta.resource ?? 'unknown'),
      )
      const scope =
        (meta.scope === undefined ? undefined : iamAsScopeLiteral<TScope>(meta.scope)) ?? getScope?.(request)

      const resourceId = getResourceId(request)
      const attributes = getResourceAttributes
        ? await getResourceAttributes(request, { action, resource, resourceId, scope })
        : {}
      return await engine.can(
        userId,
        action,
        { type: resource, id: resourceId, attributes },
        getEnvironment(request),
        scope,
      )
    } catch (err) {
      return onError(err instanceof Error ? err : new Error(String(err)), request)
    }
  }
}

/**
 * Resource type from the route template's first literal segment, else {@link iamDefaultResource} on the raw path.
 * SECURITY: a `%` or `*` template segment gives {@link IAM_UNKNOWN_RESOURCE}; `'*'` is the engine's wildcard pattern.
 */
function inferResource(request: NestRequest): string {
  // SECURITY: before the template branch: a matched template does not make an ambiguous target safe
  // (`/public/../admin` matches `/public/*`).
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
 * Error carrying both `status` (for express-style consumers) and `statusCode`.
 * INFO: Nest's base filter answers 500 for a non-`HttpException` unless it has `statusCode` and a message.
 */
function adminHttpError(message: string, statusCode: number): Error {
  return Object.assign(new Error(message), { status: statusCode, statusCode })
}

/**
 * Builds admin operations to wire into `@Controller` methods, since Nest routes by decorator, not router.
 * Requires `authorize` at construction, so the controller cannot be built unguarded.
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
 * Rate limiting is out of scope; compose with `@nestjs/throttler` or a global guard (pseudocode):
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
  const { authorize, onAdminMutation, getMutationActor, redactPath, onAuditHookError, includeErrorMessage, csrfCheck } =
    opts
  // Default to the built-in Sec-Fetch-Site check; pass `false` to disable.
  const effectiveCsrfCheck = csrfCheck === false ? null : (csrfCheck ?? iamDefaultCsrfCheck)
  iamNoticeCsrfDefaultIfNeeded(csrfCheck !== undefined)

  const onUnauthorized = opts.onUnauthorized ?? (() => adminHttpError('Unauthorized', 401))
  const onForbidden = opts.onForbidden ?? (() => adminHttpError('Forbidden (CSRF check failed)', 403))
  // The original rides along as `cause`: kept for a logger that walks the chain, out of the response.
  const onError =
    opts.onError ?? ((err: Error) => Object.assign(adminHttpError('Internal server error', 500), { cause: err }))

  /**
   * A validation failure becomes a 400 carrying `issues`, which describe the caller's own document and are safe to
   * return; anything else goes through `onError`.
   */
  const asThrowable = (err: unknown, req: NestRequest): Error => {
    if (hasIamErrorCode(err, 'IAM_VALIDATION_FAILED')) {
      return Object.assign(adminHttpError(`Invalid ${err.meta.kind}`, 400), { cause: err, issues: err.meta.issues })
    }
    return onError(err instanceof Error ? err : new Error(String(err)), req)
  }

  /**
   * The shared {@link iamRunAdminAuthz} gate, returning the nameable actor for the audit event.
   * Throws `onForbidden` (CSRF), `onUnauthorized` (refused), or `onError` (a throwing `authorize`).
   */
  const gateWithActor = async (req: NestRequest): Promise<IamAdminActor | undefined> => {
    // SECURITY: CSRF runs before authorize, so a cookie-based authorize cannot be ridden by a cross-origin POST.
    const authz = await iamRunAdminAuthz(req, effectiveCsrfCheck, authorize)
    if (authz.phase === 'forbidden') throw onForbidden(req)
    if (authz.phase === 'unauthorized') throw onUnauthorized(req)
    // A throwing `authorize` is a server fault, not the caller's: `onError` gives it a status, keeping it as `cause`.
    if (authz.phase === 'error') throw onError(authz.error, req)
    return authz.actor
  }

  /** Runs a mutation through the audit wrapper, so the event lands even when the handler throws. */
  const runMutation = async <T>(
    req: NestRequest,
    action: IamAdminAudit.Action,
    target: IamAdminAudit.Target,
    targetId: string | undefined,
    handler: (who: { actor?: string }) => Promise<T>,
  ): Promise<T> => {
    // A gate refusal throws before the wrapper, so no audit event fires: the mutation never started.
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
        () => handler(iamAdminActorOptions(actor, getMutationActor)),
      )
    } catch (err) {
      // The wrapper has already audited the failure; `asThrowable` only decides what the framework sees.
      throw asThrowable(err, req)
    }
  }

  /** Read gate: the same CSRF and `authorize` phase as a mutation, with no audit event. */
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
      // `iamAuditIdOf`, not a cast: the declared type is only what the controller promises, not the JSON that arrived.
      return runMutation(req, 'replace', 'policy', iamAuditIdOf(body), async (who) => {
        await engine.admin.savePolicy(body, who)
        return { ok: true as const }
      })
    },
    async saveRole(req: NestRequest, body: AccessControl.IRole<TAction, TResource, TRole, TScope>) {
      return runMutation(req, 'replace', 'role', iamAuditIdOf(body), async (who) => {
        await engine.admin.saveRole(body, who)
        return { ok: true as const }
      })
    },
    /**
     * Validates the id and body at the edge, since `@Param`/`@Body` types are unchecked promises; inside `runMutation`,
     * so a refusal is audited as a failure.
     */
    async assignRole(req: NestRequest, subjectId: string, body: { roleId: TRole; scope?: TScope }) {
      return runMutation(req, 'create', 'role-assignment', subjectId, async (who) => {
        const scope = iamOptionalStringField(body, 'scope')
        await engine.admin.assignRole(
          iamRequirePathParam(subjectId, 'id'),
          iamAsRoleLiteral<TRole>(iamRequireStringField(body, 'roleId')),
          scope === undefined ? undefined : iamAsScopeLiteral<TScope>(scope),
          who,
        )
        return { ok: true as const }
      })
    },
    async revokeRole(req: NestRequest, subjectId: string, roleId: TRole) {
      return runMutation(req, 'delete', 'role-assignment', subjectId, async (who) => {
        await engine.admin.revokeRole(
          iamRequirePathParam(subjectId, 'id'),
          iamAsRoleLiteral<TRole>(iamRequirePathParam(roleId, 'roleId')),
          undefined,
          who,
        )
        return { ok: true as const }
      })
    },
  }
}
