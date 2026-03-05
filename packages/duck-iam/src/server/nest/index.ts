import type { Engine } from '../../core/engine'
import type { Environment } from '../../core/types'
import { extractEnvironment, METHOD_ACTION_MAP } from '../generic'

// Reflect.defineMetadata/getMetadata come from reflect-metadata (used by NestJS)
declare namespace Reflect {
  function defineMetadata(key: string, value: unknown, target: object): void
  function getMetadata(key: string, target: object): unknown
}

// -- Minimal NestJS types -- no hard dependency on @nestjs/common --

interface NestRequest {
  user?: { id?: string; sub?: string; [key: string]: unknown }
  params?: Record<string, string>
  method: string
  path?: string
  route?: { path?: string }
  headers?: Record<string, string | string[] | undefined>
  ip?: string
  [key: string]: unknown
}

interface NestExecutionContext {
  switchToHttp(): { getRequest(): NestRequest }
  // NestJS returns Function -- we use `object` as the compatible supertype
  getHandler(): object
}

// -- Metadata key for the decorator --
export const ACCESS_METADATA_KEY = 'duck-iam:authorize'

// -- Types for decorator config --
export interface AuthorizeMeta<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> {
  action?: TAction
  resource?: TResource
  scope?: TScope
  /** If true, infer action from HTTP method and resource from route path */
  infer?: boolean
}

interface HandlerWithMeta {
  __accessMeta?: AuthorizeMeta
}

/**
 * Decorator: mark a controller method with access requirements.
 *
 *   @Authorize({ action: 'delete', resource: 'post' })
 *   @Authorize({ action: 'manage', resource: 'user', scope: 'admin' })
 */
export function Authorize<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  meta: AuthorizeMeta<TAction, TResource, TScope> = { infer: true } as AuthorizeMeta<TAction, TResource, TScope>,
): MethodDecorator {
  return (target, propertyKey, descriptor) => {
    // Use Reflect.defineMetadata if available, otherwise fallback
    if (typeof Reflect !== 'undefined' && Reflect.defineMetadata) {
      Reflect.defineMetadata(ACCESS_METADATA_KEY, meta, descriptor.value as object)
    }
    // Attach directly as well for guard to read
    if (descriptor.value != null) {
      Object.defineProperty(descriptor.value, '__accessMeta', { value: meta, configurable: true, writable: true })
    }
    return descriptor
  }
}

/**
 * Guard factory for NestJS.
 */
export interface NestGuardOptions<TScope extends string = string> {
  getUserId?: (request: NestRequest) => string | null
  getEnvironment?: (request: NestRequest) => Environment
  getResourceId?: (request: NestRequest) => string | undefined
  getScope?: (request: NestRequest) => TScope | undefined
  onError?: (err: Error, request: NestRequest) => boolean
}

function getHandlerMeta(handler: object): AuthorizeMeta | undefined {
  // Check property attached by @Authorize decorator
  if ('__accessMeta' in handler) {
    return (handler as HandlerWithMeta).__accessMeta
  }
  // Fall back to Reflect metadata
  if (typeof Reflect !== 'undefined' && Reflect.getMetadata) {
    return Reflect.getMetadata(ACCESS_METADATA_KEY, handler) as AuthorizeMeta | undefined
  }
  return undefined
}

export function nestAccessGuard<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: Engine<TAction, TResource, TRole, TScope>, opts: NestGuardOptions<TScope> = {}) {
  const {
    getUserId = (req: NestRequest) => (req.user?.id as string) ?? (req.user?.sub as string) ?? null,
    getEnvironment = (req: NestRequest) => extractEnvironment(req),
    getResourceId = (req: NestRequest) => req.params?.id,
    getScope,
    onError = () => false,
  } = opts

  return async (context: NestExecutionContext): Promise<boolean> => {
    const request = context.switchToHttp().getRequest()
    const handler = context.getHandler()

    const meta = getHandlerMeta(handler)

    if (!meta) return true // No @Authorize decorator = allow

    const userId = getUserId(request)
    if (!userId) return false

    const action = meta.infer ? (METHOD_ACTION_MAP[request.method] ?? 'read') : (meta.action ?? 'read')

    const resource = meta.infer ? inferResource(request) : (meta.resource ?? 'unknown')

    // Scope from decorator takes precedence, then from request extractor
    const scope = (meta.scope as TScope | undefined) ?? getScope?.(request)

    try {
      return await engine.can(
        userId,
        action as TAction,
        { type: resource as TResource, id: getResourceId(request), attributes: {} },
        getEnvironment(request),
        scope,
      )
    } catch (err) {
      return onError(err as Error, request)
    }
  }
}

function inferResource(request: NestRequest): string {
  const path: string = request.route?.path ?? request.path ?? '/'
  const segments = path.split('/').filter((s: string) => s && !s.startsWith(':'))
  return segments[segments.length - 1] ?? 'root'
}

/**
 * Create a pre-typed Authorize decorator constrained to your app's actions/resources/scopes.
 * Typos like `@Authorize({ action: 'craete' })` become compile errors.
 *
 *   const Authorize = createTypedAuthorize<AppAction, AppResource, AppScope>()
 *
 *   @Authorize({ action: 'delete', resource: 'post' }) // ok - type-checked
 *   @Authorize({ action: 'typo' })                     // err - compile error
 */
export function createTypedAuthorize<
  TAction extends string,
  TResource extends string,
  TScope extends string = string,
>() {
  return Authorize as (meta?: AuthorizeMeta<TAction, TResource, TScope>) => MethodDecorator
}

export const ACCESS_ENGINE_TOKEN = 'ACCESS_ENGINE'

/**
 * Helper to create a NestJS provider for the Engine.
 */
export function createEngineProvider<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(factory: () => Engine<TAction, TResource, TRole, TScope> | Promise<Engine<TAction, TResource, TRole, TScope>>) {
  return {
    provide: ACCESS_ENGINE_TOKEN,
    useFactory: factory,
  }
}
