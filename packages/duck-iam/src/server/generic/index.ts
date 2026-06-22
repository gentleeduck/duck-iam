import type { IamEngine } from '../../core'
import type { IamClient, IamRequest } from '../../core/types'

/**
 * Shared admin-mutation audit event shape.
 *
 * Every framework adapter (express, hono, next, nest) accepts an optional
 * `onAdminMutation` callback in its admin-router options. The callback fires
 * once per mutation (PUT/POST/DELETE/PATCH) after the handler completes,
 * regardless of success or failure. It is fire-and-forget - adapters never
 * `await` it inline - so a slow or throwing hook can never block, fail, or
 * leak timing information back to the caller. Errors inside the hook are
 * caught and one-line-logged via `console.error`.
 *
 * GET (read) handlers never fire the hook.
 *
 * Rate-limit throttling is out of scope; callers compose their own rate-limit
 * middleware around the admin router. See each adapter's JSDoc for a pattern.
 */
export namespace IamAdminAudit {
  /** Categorical action describing what changed. */
  export type Action = 'create' | 'update' | 'delete' | 'replace'
  /** Categorical target describing what kind of object was changed. */
  export type Target = 'policy' | 'role' | 'assignment' | 'role-assignment' | 'attributes'

  /**
   * Describes a single admin mutation event.
   *
   * Field-level semantics worth calling out:
   *
   * - `path` - By default carries the request URL **including any expanded
   *   route parameters** (e.g. `/admin/policies/policy-123/tenant-acme`).
   *   That string therefore can contain tenant IDs, subject IDs, role IDs,
   *   and other potentially sensitive identifiers. To redact, pass
   *   {@link IOptions.redactPath} on the adapter's admin options.
   * - `error` - By default this is the **error class name only** (e.g.
   *   `'TypeError'`, `'PolicyValidationError'`), NOT `err.message`. The
   *   message can leak credentials, query fragments, or SQL when the
   *   downstream throw originates in a DB driver. To restore the full
   *   message, pass {@link IOptions.includeErrorMessage} `true` on the
   *   adapter's admin options.
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

  /** Audit-hook signature. Sync or async; never awaited by the adapter. */
  export type Hook = (event: IEvent) => void | Promise<void>

  /**
   * Shared audit-hook hardening options.
   *
   * Every framework adapter's admin-router options interface composes this
   * shape, so the hardening surface is identical across express/hono/next/
   * nest. All fields are optional and additive - the legacy hook behaviour
   * is preserved when none are supplied.
   */
  export interface IOptions {
    /**
     * Optional redactor applied to {@link IEvent.path} before the hook
     * receives the event.
     *
     * The default `event.path` carries the request URL including expanded
     * route parameters - e.g. `/admin/policies/policy-123/tenant-acme` -
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
     * Invoked when the hook itself throws (sync or async). The default sink
     * is `console.error`; supply this to route hook failures into your
     * logger or metrics pipeline. Errors thrown by `onAuditHookError` itself
     * are caught and last-resort-logged via `console.error` - they never
     * propagate.
     */
    onAuditHookError?: (err: unknown, event: IEvent) => void
    /**
     * When `true`, populate {@link IEvent.error} with `err.message`. The
     * default is the error **class name** because downstream DB-driver
     * errors can carry credentials, query fragments, or SQL inside their
     * message. Only enable this if you control the throw sites and the
     * audit sink.
     */
    includeErrorMessage?: boolean
    /**
     * CSRF guard for state-changing admin mutations.
     *
     * Default (`undefined`): a built-in `Sec-Fetch-Site` check rejects
     * cross-site browser requests - browsers populate the header
     * automatically; its absence indicates a non-browser caller (curl,
     * server-to-server, native app) and is allowed. This default closes
     * the most common cookie-auth admin-CSRF vector without operator
     * action.
     *
     * Pass `false` to disable entirely (server-to-server with bearer
     * tokens / mTLS that intentionally posts cross-site). Pass a function
     * to supply a stricter check - e.g. an Origin allowlist:
     *
     * @example
     * ```ts
     * // Default - uses built-in Sec-Fetch-Site check
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

/** Per-process latch so the CSRF default notice fires at most once. */
let _CSRF_DEFAULT_NOTICED = false

/**
 * Log a one-time notice on first admin-router construction so operators
 * upgrading from 2.0.x are explicitly told the default changed. Suppressed
 * when the operator passed `csrfCheck` (any value including `false`).
 *
 * Called by every framework adapter exactly once at construction.
 */
export function iamNoticeCsrfDefaultIfNeeded(csrfCheckPassed: boolean): void {
  if (csrfCheckPassed || _CSRF_DEFAULT_NOTICED) return
  _CSRF_DEFAULT_NOTICED = true
  // eslint-disable-next-line no-console
  console.info(
    '[@gentleduck/iam] admin router: default CSRF check enabled - ' +
      'rejecting browser requests with Sec-Fetch-Site: cross-site|cross-origin. ' +
      'Pass `csrfCheck: false` for bearer-token/mTLS APIs, or supply a custom ' +
      'predicate. See SECURITY.md "Admin router CSRF" section. (2.1.0 behavior change)',
  )
}

/**
 * Default CSRF predicate: reject browser requests whose `Sec-Fetch-Site`
 * header is `'cross-site'` or `'cross-origin'`. Same-origin and same-site
 * requests pass; non-browser callers (no header set) pass.
 *
 * @param req - Any object the adapter can extract a header from.
 * @returns `true` to allow, `false` to reject (403).
 */

export function iamDefaultCsrfCheck(req: unknown): boolean {
  const r = req as
    | {
        headers?: Record<string, string | string[] | undefined> | { get?: (n: string) => string | null }
        req?: { header?: (n: string) => string | undefined }
      }
    | undefined
  let site: string | undefined
  // IamExpress/IamNest-style: req.headers is a Record.
  const recordHeaders = r?.headers
  if (recordHeaders && typeof (recordHeaders as { get?: unknown }).get !== 'function') {
    const v = (recordHeaders as Record<string, string | string[] | undefined>)['sec-fetch-site']
    site = Array.isArray(v) ? v[0] : v
  }
  // Next/fetch-API style: req.headers.get(...).
  if (!site && recordHeaders && typeof (recordHeaders as { get?: unknown }).get === 'function') {
    site = (recordHeaders as { get: (n: string) => string | null }).get('sec-fetch-site') ?? undefined
  }
  // IamHono style: c.req.header(...).
  if (!site && r?.req?.header) {
    site = r.req.header('sec-fetch-site')
  }
  if (!site) return true // non-browser caller; let bearer/mTLS auth decide
  return site !== 'cross-site' && site !== 'cross-origin'
}

/**
 * Composable admin-mutation audit wrapper. Runs `handler` inside
 * try/catch/finally, capturing success/failure for the audit event and
 * surfacing the operator-friendly error string.
 *
 * Re-throws the original error so the caller's catch can build the
 * framework-specific error response. The audit always fires (via finally).
 *
 * @template T - Handler return type.
 * @param ctx - Audit payload + hooks shared across framework adapters.
 * @param handler - The actual mutation function (e.g. `engine.admin.savePolicy`).
 */
export async function iamWithAdminAudit<T>(
  ctx: {
    actor: unknown
    action: IamAdminAudit.Action
    target: IamAdminAudit.Target
    targetId?: string
    method: string
    path: string
    onAdminMutation?: IamAdminAudit.Hook
    redactPath?: (path: string) => string
    onAuditHookError?: (err: unknown, event: IamAdminAudit.IEvent) => void
    includeErrorMessage?: boolean
  },
  handler: () => Promise<T>,
): Promise<T> {
  let success = false
  let errorMessage: string | undefined
  try {
    const out = await handler()
    success = true
    return out
  } catch (err) {
    errorMessage = iamErrorToAuditString(err, ctx.includeErrorMessage)
    throw err
  } finally {
    iamFireAdminMutation(
      ctx.onAdminMutation,
      {
        actor: ctx.actor,
        action: ctx.action,
        target: ctx.target,
        targetId: ctx.targetId,
        ts: Date.now(),
        method: ctx.method,
        path: ctx.path,
        success,
        error: errorMessage,
      },
      { redactPath: ctx.redactPath, onAuditHookError: ctx.onAuditHookError },
    )
  }
}

/**
 * Result of {@link iamRunAdminAuthz}. Discriminated union so the framework
 * adapter can branch on the phase and produce its own response.
 */
export type IamIAdminAuthzResult =
  | { phase: 'forbidden' }
  | { phase: 'unauthorized' }
  | { phase: 'error'; error: Error }
  | { phase: 'ok'; actor: unknown }

/**
 * Run the CSRF + authorize phases shared by every admin route.
 * Discriminated-union return lets each framework adapter map to its own
 * response shape (express writes to `res`, hono/next return `Response`, nest
 * throws). The catch arm wraps thrown values into a normal `Error`.
 */
export async function iamRunAdminAuthz<TReq>(
  req: TReq,
  csrfCheck: ((req: TReq) => boolean) | null,
  authorize: (req: TReq) => unknown | Promise<unknown>,
): Promise<IamIAdminAuthzResult> {
  if (csrfCheck && !csrfCheck(req)) return { phase: 'forbidden' }
  let actor: unknown
  try {
    actor = await authorize(req)
  } catch (err) {
    return { phase: 'error', error: err instanceof Error ? err : new Error(String(err)) }
  }
  if (!actor) return { phase: 'unauthorized' }
  return { phase: 'ok', actor }
}

/**
 * Derive an audit-friendly string from an unknown thrown value.
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
 * @returns A stable string suitable for {@link IamAdminAudit.IEvent.error}.
 */
export function iamErrorToAuditString(err: unknown, includeMessage?: boolean): string {
  if (includeMessage) {
    if (err instanceof Error) return err.message
    if (err === undefined) return 'undefined'
    if (err === null) return 'null'
    // Tag non-Error throws and cap length so audit sinks never receive an
    // unbounded raw value (e.g. a thrown secret string).
    const raw = typeof err === 'string' ? err : safeStringify(err)
    const capped = raw.length > NON_ERROR_MESSAGE_CAP ? `${raw.slice(0, NON_ERROR_MESSAGE_CAP)}...` : raw
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

/** 256 chars is enough to identify a thrown shape without exfil. */
const NON_ERROR_MESSAGE_CAP = 256

/**
 * Safely coerce a non-Error throw to string. Plain `String(obj)` returns
 * `[object Object]` for most objects; we try `JSON.stringify` first to surface
 * useful detail, but swallow circular-ref throws and fall back to `String()`.
 */
function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? String(v)
  } catch {
    return String(v)
  }
}

/**
 * Fire-and-forget invoker for an {@link IamAdminAudit.Hook}.
 *
 * Resolves any returned promise off the request critical path. Applies
 * {@link IamAdminAudit.IOptions.redactPath} to `event.path` before invoking the
 * hook so route parameters never reach the sink. Routes thrown errors (sync
 * or async) to {@link IamAdminAudit.IOptions.onAuditHookError} when configured,
 * falling back to `console.error` with a one-line tag. The hook can never
 * block, fail, or destabilise the response.
 *
 * @param hook - Optional caller-supplied hook; no-op when absent.
 * @param event - Event payload describing the mutation.
 * @param opts - Optional hardening options (path redaction, hook-error sink).
 */
export function iamFireAdminMutation(
  hook: IamAdminAudit.Hook | undefined,
  event: IamAdminAudit.IEvent,
  opts?: Pick<IamAdminAudit.IOptions, 'redactPath' | 'onAuditHookError'>,
): void {
  if (!hook) return

  // Redact path before the hook ever sees it.
  if (opts?.redactPath) {
    try {
      event.path = opts.redactPath(event.path)
    } catch (err) {
      // Redactor itself blew up - treat as a hook error.
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
 * Routes a hook failure to the caller-supplied
 * {@link IamAdminAudit.IOptions.onAuditHookError} when configured, otherwise to
 * `console.error`. Errors from `onAuditHookError` itself never propagate;
 * they fall through to a last-resort `console.error`.
 */
function reportAuditHookError(
  err: unknown,
  event: IamAdminAudit.IEvent,
  sink: IamAdminAudit.IOptions['onAuditHookError'],
): void {
  if (sink) {
    try {
      sink(err, event)
      return
    } catch (sinkErr) {
      // Sink itself threw - last-resort log, then stop.
      try {
        console.error(
          '[@gentleduck/iam] onAuditHookError sink threw:',
          sinkErr instanceof Error ? sinkErr.message : String(sinkErr),
        )
      } catch {
        // console.error itself failed (extremely unusual) - give up silently.
      }
      return
    }
  }
  try {
    console.error('[@gentleduck/iam] onAdminMutation hook threw:', err instanceof Error ? err.message : String(err))
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
 */
export async function generateIamPermissionMap<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  engine: IamEngine<TAction, TResource, TRole, TScope>,
  subjectId: string,
  checks: readonly IamClient.IPermissionCheck<TAction, TResource, TScope>[],
  environment?: IamRequest.IEnvironment,
): Promise<IamClient.PermissionMap<TAction, TResource, TScope>> {
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
 * const can = createIamSubjectCan(engine, req.user.id)
 * if (await can('delete', 'post')) { ... }
 * ```
 */
export function createIamSubjectCan<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(engine: IamEngine<TAction, TResource, TRole, TScope>, subjectId: string, environment?: IamRequest.IEnvironment) {
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
 * @returns The extracted {@link IamRequest.IEnvironment}.
 */
export function iamExtractEnvironment(req: {
  ip?: string
  headers?: Record<string, string | string[] | undefined> | Headers
  method?: string
  url?: string
}): IamRequest.IEnvironment {
  const getHeader = (name: string): string | undefined => {
    if (!req.headers) return undefined
    if (req.headers instanceof Headers) return req.headers.get(name) ?? undefined
    const val = req.headers[name]
    return Array.isArray(val) ? val[0] : val
  }

  return {
    // XFF can carry multiple comma-separated values (one per proxy hop,
    // leftmost is the original client). Apps behind multiple trusted
    // proxies should bypass this helper and assemble `env.ip` themselves.
    ip: req.ip ?? normalizeForwardedFor(getHeader('x-forwarded-for')) ?? normalizeForwardedFor(getHeader('x-real-ip')),
    userAgent: getHeader('user-agent'),
    timestamp: Date.now(),
  }
}

/**
 * Extract the leftmost client IP from an `X-Forwarded-For` / `X-Real-IP`
 * header. Returns undefined for missing, empty, or oversized input.
 */
function normalizeForwardedFor(raw: string | undefined): string | undefined {
  if (typeof raw !== 'string') return undefined
  if (raw.length === 0 || raw.length > 4096) return undefined
  const first = raw.split(',', 1)[0]
  if (first === undefined) return undefined
  const trimmed = first.trim()
  if (trimmed.length === 0) return undefined
  if (trimmed.length > 256) return undefined
  return trimmed
}

/** Maps HTTP methods to default access actions used by the framework adapters. */
export const IAM_METHOD_ACTION_MAP: Readonly<Record<string, string>> = {
  GET: 'read',
  HEAD: 'read',
  OPTIONS: 'read',
  POST: 'create',
  PUT: 'update',
  PATCH: 'update',
  DELETE: 'delete',
}
