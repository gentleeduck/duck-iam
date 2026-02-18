import type { Engine } from '../../core/engine'
import type { Environment, Resource } from '../../core/types'
import { extractEnvironment, METHOD_ACTION_MAP } from '../generic'

/**
 * NestJS integration for access-engine.
 *
 * Setup:
 *   1. Provide the Engine in your module
 *   2. Use @Authorize() decorator on controllers/routes
 *   3. Register AccessGuard globally or per-controller
 *
 * Example module setup:
 *
 *   @Module({
 *     providers: [
 *       {
 *         provide: 'ACCESS_ENGINE',
 *         useFactory: () => new Engine({ adapter: new PrismaAdapter(prisma) }),
 *       },
 *       AccessGuard,
 *       AccessService,
 *     ],
 *   })
 *   export class AccessModule {}
 */

// ── Metadata key for the decorator ──
export const ACCESS_METADATA_KEY = 'access-engine:authorize'

// ── Types for decorator config ──
export interface AuthorizeMeta {
  action?: string
  resource?: string
  /** If true, infer action from HTTP method and resource from route path */
  infer?: boolean
}

/**
 * Decorator: mark a controller method with access requirements.
 *
 *   @Authorize({ action: "delete", resource: "post" })
 *   @Delete(":id")
 *   async deletePost(@Param("id") id: string) { ... }
 *
 *   // Or auto-infer from HTTP method + route:
 *   @Authorize({ infer: true })
 *   @Get("posts")
 *   async listPosts() { ... }
 */
export function Authorize(meta: AuthorizeMeta = { infer: true }): MethodDecorator {
  return (target, propertyKey, descriptor) => {
    // Use Reflect.defineMetadata if available, otherwise fallback
    if (typeof Reflect !== 'undefined' && Reflect.defineMetadata) {
      Reflect.defineMetadata(ACCESS_METADATA_KEY, meta, descriptor.value as object)
    }
    // Attach directly as well for guard to read
    ;(descriptor.value as any).__accessMeta = meta
    return descriptor
  }
}

/**
 * Guard factory for NestJS.
 *
 * Usage with dependency injection:
 *
 *   @Injectable()
 *   export class AccessGuard implements CanActivate {
 *     constructor(@Inject('ACCESS_ENGINE') private engine: Engine) {}
 *
 *     canActivate(context: ExecutionContext): Promise<boolean> {
 *       return createAccessGuard(this.engine)(context);
 *     }
 *   }
 *
 * Or use the factory directly:
 *
 *   const guard = nestAccessGuard(engine, { getUserId: (req) => req.user.sub });
 */
export interface NestGuardOptions {
  getUserId?: (request: any) => string | null
  getEnvironment?: (request: any) => Environment
  getResourceId?: (request: any) => string | undefined
}

export function nestAccessGuard(engine: Engine, opts: NestGuardOptions = {}) {
  const {
    getUserId = (req: any) => req.user?.id ?? req.user?.sub ?? null,
    getEnvironment = (req: any) => extractEnvironment(req),
    getResourceId = (req: any) => req.params?.id,
  } = opts

  /**
   * This returns a function compatible with NestJS CanActivate.canActivate()
   * when you pass it the ExecutionContext.
   */
  return async (context: any): Promise<boolean> => {
    const request = context.switchToHttp().getRequest()
    const handler = context.getHandler()

    const meta: AuthorizeMeta | undefined =
      handler.__accessMeta ??
      (typeof Reflect !== 'undefined' && Reflect.getMetadata
        ? Reflect.getMetadata(ACCESS_METADATA_KEY, handler)
        : undefined)

    if (!meta) return true // No @Authorize decorator = allow

    const userId = getUserId(request)
    if (!userId) return false

    const action = meta.infer ? (METHOD_ACTION_MAP[request.method] ?? 'read') : (meta.action ?? 'read')

    const resource = meta.infer ? inferResource(request) : (meta.resource ?? 'unknown')

    return engine.can(
      userId,
      action,
      { type: resource, id: getResourceId(request), attributes: {} },
      getEnvironment(request),
    )
  }
}

function inferResource(request: any): string {
  const path: string = request.route?.path ?? request.path ?? '/'
  const segments = path.split('/').filter((s: string) => s && !s.startsWith(':'))
  return segments[segments.length - 1] ?? 'root'
}

/**
 * Injectable service for use in NestJS controllers/services.
 *
 *   @Injectable()
 *   export class AccessService {
 *     constructor(@Inject('ACCESS_ENGINE') private engine: Engine) {}
 *
 *     can(userId: string, action: string, resource: string) {
 *       return this.engine.can(userId, action, { type: resource, attributes: {} });
 *     }
 *
 *     permissions(userId: string, checks: PermissionCheck[]) {
 *       return this.engine.permissions(userId, checks);
 *     }
 *   }
 *
 * This is just a pattern suggestion; use Engine directly via DI.
 */
export const ACCESS_ENGINE_TOKEN = 'ACCESS_ENGINE'

/**
 * Helper to create a NestJS provider for the Engine.
 *
 *   @Module({
 *     providers: [
 *       createEngineProvider(() => new Engine({ adapter: myAdapter })),
 *     ],
 *   })
 */
export function createEngineProvider(factory: () => Engine | Promise<Engine>) {
  return {
    provide: ACCESS_ENGINE_TOKEN,
    useFactory: factory,
  }
}
