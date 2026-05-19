import type { Engine } from '../../core'
import type { Client, Request } from '../../core/types'

/**
 * SEC-010: shared admin-mutation audit event shape.
 *
 * Every framework adapter (express, hono, next, nest) accepts an optional
 * `onAdminMutation` callback in its admin-router options. The callback fires
 * once per mutation (PUT/POST/DELETE/PATCH) after the handler completes,
 * regardless of success or failure. It is fire-and-forget — adapters never
 * `await` it inline — so a slow or throwing hook can never block, fail, or
 * leak timing information back to the caller. Errors inside the hook are
 * caught and one-line-logged via `console.error`.
 *
 * GET (read) handlers never fire the hook.
 *
 * Rate-limit-style throttling is intentionally out of scope here — callers
 * compose their own rate-limit middleware around the admin router (e.g.
 * `express-rate-limit`, hono `bun-rate-limit`, etc.). See each adapter's
 * JSDoc for a documented pattern.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export namespace AdminAudit {
  /** Categorical action describing what changed. */
  export type Action = 'create' | 'update' | 'delete' | 'replace'
  /** Categorical target describing what kind of object was changed. */
  export type Target = 'policy' | 'role' | 'assignment' | 'role-assignment' | 'attributes'

  /**
   * Describes a single admin mutation event.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IEvent {
    /** Whatever the adapter's `authorize` callback returned (often a user/JWT claims object). */
    actor?: unknown
    /** Semantic verb. */
    action: Action
    /** Semantic noun. */
    target: Target
    /** Optional identifier of the target object (e.g. policy id, subject id). */
    targetId?: string
    /** Event timestamp from `Date.now()`. */
    ts: number
    /** HTTP method that triggered the mutation. */
    method: string
    /** HTTP path that triggered the mutation. */
    path: string
    /** Whether the handler completed without throwing. */
    success: boolean
    /** Stringified error message when `success === false`. */
    error?: string
  }

  /**
   * Audit-hook signature. Sync or async; never awaited by the adapter.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export type Hook = (event: IEvent) => void | Promise<void>
}

/**
 * SEC-010: fire-and-forget invoker for an {@link AdminAudit.Hook}.
 *
 * Resolves any returned promise off the request critical path and routes
 * thrown errors (sync or async) to `console.error` with a one-line tag. The
 * hook can never block, fail, or destabilise the response.
 *
 * @param hook - Optional caller-supplied hook; no-op when absent.
 * @param event - Event payload describing the mutation.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function fireAdminMutation(hook: AdminAudit.Hook | undefined, event: AdminAudit.IEvent): void {
  if (!hook) return
  try {
    Promise.resolve(hook(event)).catch((err) =>
      console.error('[duck-iam] onAdminMutation hook threw:', err instanceof Error ? err.message : String(err)),
    )
  } catch (err) {
    console.error('[duck-iam] onAdminMutation hook threw:', err instanceof Error ? err.message : String(err))
  }
}
/**
 * Builds a server-side permission map for a subject and a list of checks.
 *
 * Call once per request and forward the map to the client.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param subjectId - Identifies the subject whose permissions are computed.
 * @param checks - Lists the permission tuples to evaluate.
 * @param environment - Optional environment context shared across checks.
 * @returns A permission map keyed by `(action, resource, scope)` tuple.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export async function generatePermissionMap<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: Engine<TAction, TResource, TRole, TScope>,
  subjectId: string,
  checks: readonly Client.IPermissionCheck<TAction, TResource, TScope>[],
  environment?: Request.IEnvironment,
): Promise<Client.PermissionMap<TAction, TResource, TScope>> {
  return engine.permissions(subjectId, checks, environment)
}

/**
 * Builds a typed `can(action, resourceType, ...)` function bound to a subject.
 *
 * Useful inside request handlers for terse permission checks.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @param engine - Provides the access engine to consult.
 * @param subjectId - Identifies the subject the returned function checks.
 * @param environment - Optional environment context applied to every check.
 * @returns A `(action, resourceType, resourceId?, scope?) => Promise<boolean>` checker.
 * @example
 * ```ts
 * const can = createSubjectCan(engine, req.user.id)
 * if (await can('delete', 'post')) { ... }
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function createSubjectCan<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: Engine<TAction, TResource, TRole, TScope>, subjectId: string, environment?: Request.IEnvironment) {
  return (action: TAction, resourceType: TResource, resourceId?: string, scope?: TScope) =>
    engine.can(subjectId, action, { type: resourceType, id: resourceId, attributes: {} }, environment, scope)
}

/**
 * Extracts an environment object from common request shapes.
 *
 * Looks at `req.ip`, `x-forwarded-for`, `x-real-ip`, and `user-agent`, and
 * stamps the current timestamp.
 *
 * @param req - Provides any request-like object with `ip` and/or `headers`.
 * @returns The extracted {@link Request.IEnvironment}.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function extractEnvironment(req: {
  ip?: string
  headers?: Record<string, string | string[] | undefined> | Headers
  method?: string
  url?: string
}): Request.IEnvironment {
  const getHeader = (name: string): string | undefined => {
    if (!req.headers) return undefined
    if (req.headers instanceof Headers) return req.headers.get(name) ?? undefined
    const val = (req.headers as Record<string, string | string[] | undefined>)[name]
    return Array.isArray(val) ? val[0] : val
  }

  return {
    ip: req.ip ?? getHeader('x-forwarded-for') ?? getHeader('x-real-ip'),
    userAgent: getHeader('user-agent'),
    timestamp: Date.now(),
  }
}

/**
 * Maps HTTP methods to default access actions used by the framework adapters.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export const METHOD_ACTION_MAP: Readonly<Record<string, string>> = {
  GET: 'read',
  HEAD: 'read',
  OPTIONS: 'read',
  POST: 'create',
  PUT: 'update',
  PATCH: 'update',
  DELETE: 'delete',
}
