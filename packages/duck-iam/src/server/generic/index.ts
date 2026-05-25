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
   * Field-level semantics worth calling out:
   *
   * - `path` — By default carries the request URL **including any expanded
   *   route parameters** (e.g. `/admin/policies/policy-123/tenant-acme`).
   *   That string therefore can contain tenant IDs, subject IDs, role IDs,
   *   and other potentially sensitive identifiers. To redact, pass
   *   {@link IOptions.redactPath} on the adapter's admin options. See
   *   SEC-039.
   * - `error` — By default this is the **error class name only** (e.g.
   *   `'TypeError'`, `'PolicyValidationError'`), NOT `err.message`. The
   *   message can leak credentials, query fragments, or SQL when the
   *   downstream throw originates in a DB driver. To restore the full
   *   message, pass {@link IOptions.includeErrorMessage} `true` on the
   *   adapter's admin options. See SEC-041.
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
    /**
     * HTTP path that triggered the mutation. By default this is the raw
     * request path with route parameters already expanded (so it may include
     * tenant IDs, subject IDs, etc.). Use {@link IOptions.redactPath} to
     * strip or rewrite identifiers before the hook sees the value.
     */
    path: string
    /** Whether the handler completed without throwing. */
    success: boolean
    /**
     * Stringified error indicator when `success === false`. Defaults to the
     * thrown value's class name (e.g. `'TypeError'`). Set
     * {@link IOptions.includeErrorMessage} `true` on the adapter options to
     * write `err.message` instead.
     */
    error?: string
  }

  /**
   * Audit-hook signature. Sync or async; never awaited by the adapter.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export type Hook = (event: IEvent) => void | Promise<void>

  /**
   * SEC-039 / SEC-040 / SEC-041: shared audit-hook hardening options.
   *
   * Every framework adapter's admin-router options interface composes this
   * shape, so the hardening surface is identical across express/hono/next/
   * nest. All fields are optional and additive — the legacy hook behaviour
   * is preserved when none are supplied.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IOptions {
    /**
     * SEC-039: optional redactor applied to {@link IEvent.path} before the
     * hook receives the event.
     *
     * The default `event.path` carries the request URL including expanded
     * route parameters — e.g. `/admin/policies/policy-123/tenant-acme` —
     * which means tenant IDs, subject IDs and role IDs can flow into audit
     * sinks unredacted. Supply a redactor when your audit sink lives outside
     * your trust boundary.
     *
     * @example
     * ```ts
     * // Replace the last segment with `:id`.
     * redactPath: (p) => p.replace(/\/[^/]+$/, '/:id')
     * ```
     */
    redactPath?: (path: string) => string
    /**
     * SEC-040: invoked when the hook itself throws (sync or async). The
     * default sink is `console.error`; supply this to route hook failures
     * into your logger or metrics pipeline. Errors thrown by
     * `onAuditHookError` itself are caught and last-resort-logged via
     * `console.error` — they never propagate.
     */
    onAuditHookError?: (err: unknown, event: IEvent) => void
    /**
     * SEC-041: when `true`, populate {@link IEvent.error} with
     * `err.message`. The default is the error **class name** because
     * downstream DB-driver errors can carry credentials, query fragments, or
     * SQL inside their message. Only enable this if you control the throw
     * sites and the audit sink.
     */
    includeErrorMessage?: boolean
    /**
     * SEC-103: CSRF guard for state-changing admin mutations.
     *
     * Default (`undefined`): a built-in `Sec-Fetch-Site` check rejects
     * cross-site browser requests — browsers populate the header
     * automatically; its absence indicates a non-browser caller (curl,
     * server-to-server, native app) and is allowed. This default closes
     * the most common cookie-auth admin-CSRF vector without operator
     * action.
     *
     * Pass `false` to disable entirely (server-to-server with bearer
     * tokens / mTLS that intentionally posts cross-site). Pass a function
     * to supply a stricter check — e.g. an Origin allowlist:
     *
     * @example
     * ```ts
     * // Default — uses built-in Sec-Fetch-Site check
     * adminRouter(engine, { authorize })
     *
     * // Disable (bearer-token API, no browser involved)
     * adminRouter(engine, { authorize, csrfCheck: false })
     *
     * // Stricter: Origin allowlist
     * const ADMIN_ORIGINS = new Set(['https://admin.example.com'])
     * adminRouter(engine, {
     *   authorize,
     *   csrfCheck: (req) => ADMIN_ORIGINS.has(req.headers.origin),
     * })
     * ```
     */
    csrfCheck?: ((req: unknown) => boolean) | false
  }
}

/**
 * SEC-103 default CSRF predicate: reject browser requests whose
 * `Sec-Fetch-Site` header is `'cross-site'` or `'cross-origin'`. Same-origin
 * and same-site requests pass; non-browser callers (no header set) pass.
 *
 * Used by every framework adapter when the operator did not pass `csrfCheck`
 * explicitly. Pass `csrfCheck: false` to disable.
 *
 * @param req - Any object the adapter can extract a header from.
 * @returns `true` to allow, `false` to reject (403).
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function defaultCsrfCheck(req: unknown): boolean {
  const r = req as
    | {
        headers?: Record<string, string | string[] | undefined> | { get?: (n: string) => string | null }
        req?: { header?: (n: string) => string | undefined }
      }
    | undefined
  let site: string | undefined
  // Express/Nest-style: req.headers is a Record.
  const recordHeaders = r?.headers
  if (recordHeaders && typeof (recordHeaders as { get?: unknown }).get !== 'function') {
    const v = (recordHeaders as Record<string, string | string[] | undefined>)['sec-fetch-site']
    site = Array.isArray(v) ? v[0] : v
  }
  // Next/fetch-API style: req.headers.get(...).
  if (!site && recordHeaders && typeof (recordHeaders as { get?: unknown }).get === 'function') {
    site = (recordHeaders as { get: (n: string) => string | null }).get('sec-fetch-site') ?? undefined
  }
  // Hono style: c.req.header(...).
  if (!site && r?.req?.header) {
    site = r.req.header('sec-fetch-site')
  }
  if (!site) return true // non-browser caller; let bearer/mTLS auth decide
  return site !== 'cross-site' && site !== 'cross-origin'
}

/**
 * SEC-041: derive an audit-friendly string from an unknown thrown value.
 *
 * By default returns the constructor name of the thrown value (e.g.
 * `'Error'`, `'TypeError'`, `'PolicyValidationError'`) so credential-bearing
 * `err.message` strings never leak into audit sinks. When
 * `includeMessage === true`, returns `err.message` for `Error` instances and
 * `String(err)` otherwise. Non-Error throws (`undefined`, strings, numbers)
 * are handled defensively.
 *
 * @param err - The thrown value; may not be an `Error` instance.
 * @param includeMessage - When `true`, return the full message instead of the class name.
 * @returns A stable string suitable for {@link AdminAudit.IEvent.error}.
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function errorToAuditString(err: unknown, includeMessage?: boolean): string {
  if (includeMessage) {
    if (err instanceof Error) return err.message
    if (err === undefined) return 'undefined'
    if (err === null) return 'null'
    // SEC-047: a non-Error throw with includeMessage opt-in could otherwise
    // leak an unbounded raw value (e.g. a thrown secret string). Tag it as
    // a non-Error throw and cap length so audit sinks never see more than a
    // tracer plus a short fragment.
    const raw = typeof err === 'string' ? err : safeStringify(err)
    const capped = raw.length > NON_ERROR_MESSAGE_CAP ? `${raw.slice(0, NON_ERROR_MESSAGE_CAP)}…` : raw
    return `<non-Error ${typeof err}> ${capped}`
  }
  if (err instanceof Error) {
    return err.constructor?.name ?? 'Error'
  }
  if (err === undefined) return 'undefined'
  if (err === null) return 'null'
  // Primitive throw: report its JS typeof so the sink still sees something
  // categorical (e.g. 'string', 'number') rather than the value itself.
  return typeof err
}

/** SEC-047: 256 chars is enough to identify a thrown shape without exfil. */
const NON_ERROR_MESSAGE_CAP = 256

/**
 * SEC-047 helper: safely coerce a non-Error throw to string. Plain
 * `String(obj)` returns `[object Object]` for most objects; we try
 * `JSON.stringify` first to surface useful detail, but swallow circular-ref
 * throws and fall back to `String()`.
 */
function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? String(v)
  } catch {
    return String(v)
  }
}

/**
 * SEC-010 / SEC-039 / SEC-040: fire-and-forget invoker for an
 * {@link AdminAudit.Hook}.
 *
 * Resolves any returned promise off the request critical path. Applies
 * {@link AdminAudit.IOptions.redactPath} to `event.path` before invoking the
 * hook so route parameters never reach the sink. Routes thrown errors (sync
 * or async) to {@link AdminAudit.IOptions.onAuditHookError} when configured,
 * falling back to `console.error` with a one-line tag. The hook can never
 * block, fail, or destabilise the response.
 *
 * @param hook - Optional caller-supplied hook; no-op when absent.
 * @param event - Event payload describing the mutation.
 * @param opts - Optional hardening options (path redaction, hook-error sink).
 * @author wildduck2 <https://github.com/wildduck2>
 */
export function fireAdminMutation(
  hook: AdminAudit.Hook | undefined,
  event: AdminAudit.IEvent,
  opts?: Pick<AdminAudit.IOptions, 'redactPath' | 'onAuditHookError'>,
): void {
  if (!hook) return

  // SEC-039: redact path before the hook ever sees it.
  if (opts?.redactPath) {
    try {
      event.path = opts.redactPath(event.path)
    } catch (err) {
      // Redactor itself blew up — treat as a hook error.
      reportAuditHookError(err, event, opts.onAuditHookError)
      return
    }
  }

  try {
    Promise.resolve(hook(event)).catch((err) => reportAuditHookError(err, event, opts?.onAuditHookError))
  } catch (err) {
    reportAuditHookError(err, event, opts?.onAuditHookError)
  }
}

/**
 * SEC-040: routes a hook failure to the caller-supplied
 * {@link AdminAudit.IOptions.onAuditHookError} when configured, otherwise to
 * `console.error`. Errors from `onAuditHookError` itself never propagate;
 * they fall through to a last-resort `console.error`.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
function reportAuditHookError(
  err: unknown,
  event: AdminAudit.IEvent,
  sink: AdminAudit.IOptions['onAuditHookError'],
): void {
  if (sink) {
    try {
      sink(err, event)
      return
    } catch (sinkErr) {
      // Sink itself threw — last-resort log, then stop.
      try {
        console.error(
          '[duck-iam] onAuditHookError sink threw:',
          sinkErr instanceof Error ? sinkErr.message : String(sinkErr),
        )
      } catch {
        // console.error itself failed (extremely unusual) — give up silently.
      }
      return
    }
  }
  try {
    console.error('[duck-iam] onAdminMutation hook threw:', err instanceof Error ? err.message : String(err))
  } catch {
    // ignore
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
