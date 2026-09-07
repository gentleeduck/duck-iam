import type { IamEngine } from '../../core'
import type { AccessControl, IamClient, IamRequest } from '../../core/types'
import { IAM_RESERVED_REFUSAL } from '../../shared/reserved'

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
  console.info(
    '[@gentleduck/iam:generic] admin router: default CSRF check enabled - ' +
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
/** The header the default CSRF predicate reads, lowercased for comparison. */
const SEC_FETCH_SITE = 'sec-fetch-site'

/** Narrows to something with a callable `get`, i.e. a fetch-API `Headers`. */
function hasHeaderGetter(value: unknown): value is { get: (name: string) => string | null } {
  return typeof value === 'object' && value !== null && typeof Reflect.get(value, 'get') === 'function'
}

/** Narrows to a hono-style context whose `req.header(name)` reads a header. */
function hasHeaderAccessor(value: unknown): value is { req: { header: (name: string) => string | undefined } } {
  if (typeof value !== 'object' || value === null) return false
  const inner: unknown = Reflect.get(value, 'req')
  if (typeof inner !== 'object' || inner === null) return false
  return typeof Reflect.get(inner, 'header') === 'function'
}

/** First usable string in a header value that may have arrived repeated. */
function headerString(value: unknown): string | undefined {
  if (typeof value === 'string') return value
  if (!Array.isArray(value)) return undefined
  for (const entry of value) if (typeof entry === 'string') return entry
  return undefined
}

/**
 * Reads `Sec-Fetch-Site` out of whatever shape the adapter passed, **case
 * insensitively**.
 *
 * HTTP header names are case-insensitive and node happens to lowercase what it
 * parses, so reading the single key `'sec-fetch-site'` out of a Record worked
 * for express and nest and silently failed for anything else - a hand-built
 * request object, a framework that preserves the wire casing, or a consumer
 * calling this exported predicate directly with `{ 'Sec-Fetch-Site': ... }`.
 * Failing to find the header is indistinguishable from "no header was sent",
 * which this predicate reads as a non-browser caller and *allows*: the
 * cross-site request it exists to reject got through on a capital letter.
 */
function readSecFetchSite(req: unknown): string | undefined {
  if (typeof req !== 'object' || req === null) return undefined
  const headers: unknown = Reflect.get(req, 'headers')
  // Fetch-API `Headers` is already case-insensitive; ask it directly.
  if (hasHeaderGetter(headers)) {
    const found = headers.get(SEC_FETCH_SITE)
    if (found !== null && found !== '') return found
  } else if (typeof headers === 'object' && headers !== null) {
    // Express/Nest-style Record. Own keys only, compared case-insensitively:
    // an inherited `constructor` is not a header.
    for (const [name, value] of Object.entries(headers)) {
      if (name.toLowerCase() !== SEC_FETCH_SITE) continue
      const found = headerString(value)
      if (found !== undefined && found !== '') return found
    }
  }
  // Hono-style `c.req.header(name)`.
  if (hasHeaderAccessor(req)) {
    const found = req.req.header(SEC_FETCH_SITE)
    if (found !== undefined && found !== '') return found
  }
  return undefined
}

/**
 * The default CSRF check for the admin routers: refuse a browser request the
 * browser itself labelled cross-site.
 *
 * `Sec-Fetch-Site` is set by the user agent and cannot be forged by page script,
 * which is what makes it worth reading. It is absent for non-browser callers
 * (curl, a server-to-server client, an old browser), and absence is treated as
 * a pass: this check is not the authentication, it only stops a logged-in
 * browser being steered into a mutation by another origin. Bearer tokens or
 * mTLS decide the non-browser case.
 *
 * Header lookup is case-insensitive. HTTP header names are case-insensitive by
 * spec and different frameworks hand them over in different cases; matching only
 * the lowercase form let a cross-site request through whenever the runtime
 * happened to preserve `Sec-Fetch-Site` as sent.
 *
 * @param req - The framework request, in any of the three header shapes
 *              {@link readSecFetchSite} understands.
 * @returns `true` when the request may proceed.
 */
export function iamDefaultCsrfCheck(req: unknown): boolean {
  const site = readSecFetchSite(req)
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
export interface IamIAdminAuthzForbidden {
  phase: 'forbidden'
}

/** The caller is not an admin: `authorize` returned false or a falsy actor. */
export interface IamIAdminAuthzUnauthorized {
  phase: 'unauthorized'
}

/**
 * `authorize` itself threw. Distinct from `unauthorized` so a broken callback
 * is reported as a server fault rather than silently denying every admin.
 */
export interface IamIAdminAuthzError {
  phase: 'error'
  error: Error
}

/**
 * The caller may proceed.
 *
 * `actor` is whatever `authorize` returned, and is `undefined` when that value
 * cannot name anyone — `true` is a valid authorising answer and the documented
 * contract, but it is not an actor, and recording it as one would put `true` in
 * the audit trail where a user id belongs.
 */
export interface IamIAdminAuthzOk {
  phase: 'ok'
  actor: unknown
}

/** Every outcome of the shared admin gate. Exhaustive: adapters switch on `phase`. */
export type IamIAdminAuthzResult =
  | IamIAdminAuthzForbidden
  | IamIAdminAuthzUnauthorized
  | IamIAdminAuthzError
  | IamIAdminAuthzOk

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
  if (csrfCheck) {
    // A throwing predicate used to propagate out of here while a throwing
    // `authorize` was caught and reported - so whether a request was refused
    // depended on the framework adapter's outer catch, and the two phases of
    // the same gate behaved differently. A predicate that cannot answer has
    // not said yes.
    let passed: boolean
    try {
      passed = csrfCheck(req)
    } catch {
      return { phase: 'forbidden' }
    }
    if (!passed) return { phase: 'forbidden' }
  }
  let actor: unknown
  try {
    actor = await authorize(req)
  } catch (err) {
    return { phase: 'error', error: err instanceof Error ? err : new Error(String(err)) }
  }
  if (!actor) return { phase: 'unauthorized' }
  // A truthy answer authorizes the mutation - `authorize: (req) => req.user?.role
  // === 'admin'` is the documented shape and returns a boolean, so that stays
  // exactly as it was. What does not stay is `true` being written into the
  // admin audit event as the person who made the change: an audit trail that
  // names `true` as the actor cannot attribute the mutation to anybody, and
  // attribution is the whole reason the event exists. A value that names no one
  // is recorded as no one, and the operator is told once how to fix it.
  if (iamIsNameableActor(actor)) return { phase: 'ok', actor }
  noticeUnnameableActor(actor)
  return { phase: 'ok', actor: undefined }
}

/** Per-process latch so the un-nameable-actor notice fires at most once. */
let _ACTOR_NOTICED = false

function noticeUnnameableActor(actor: unknown): void {
  if (_ACTOR_NOTICED) return
  _ACTOR_NOTICED = true
  console.warn(
    `[@gentleduck/iam:generic] admin router: \`authorize\` returned ${describeActor(actor)}, which names ` +
      'no one, so admin audit events for this router will record no actor. Return the actor itself ' +
      '(a subject id, or an object identifying them) instead of whether they are allowed, ' +
      'to make admin mutations attributable.',
  )
}

/** Names the shape an un-nameable actor arrived in, for the notice above. */
function describeActor(actor: unknown): string {
  if (Array.isArray(actor)) return 'an array'
  if (typeof actor === 'string') return 'a blank string'
  return `a ${typeof actor}`
}

/**
 * Can this value be recorded as the actor who performed an admin mutation?
 *
 * A non-empty string (a subject id) or an object identifying them. Not a
 * boolean, a number, a symbol, a function or an array: none of those name a
 * person, and the admin audit event exists to name one. This is the check
 * {@link iamIsSubjectId} makes on `getUserId`, on the admin path.
 */
export function iamIsNameableActor(value: unknown): boolean {
  if (typeof value === 'string') return value.trim().length > 0
  return typeof value === 'object' && value !== null && !Array.isArray(value)
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
          '[@gentleduck/iam:generic] onAuditHookError sink threw:',
          sinkErr instanceof Error ? sinkErr.message : String(sinkErr),
        )
      } catch {
        // console.error itself failed (extremely unusual) - give up silently.
      }
      return
    }
  }
  try {
    console.error(
      '[@gentleduck/iam:generic] onAdminMutation hook threw:',
      err instanceof Error ? err.message : String(err),
    )
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
 * @param environment - Optional environment context shared across checks.
 * @returns A permission map keyed by `(action, resource, scope)` tuple.
 */
export async function generateIamPermissionMap<
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
 * **`environment.ip` is `undefined` unless you ask for it.** This helper does
 * not guess the client address, because there is no guess that is right on
 * every deployment and the wrong one is exploitable: `X-Forwarded-For` and
 * `X-Real-IP` are request headers like any other, so with nothing in front of
 * the app a client sets them itself. Against real servers, hono, next and the
 * generic helper each echoed a plain `X-Forwarded-For: 10.0.0.1` into
 * `environment.ip` and a header alone satisfied an IP-conditioned admin grant,
 * while express and nest reported the socket peer for the same request - one
 * policy, three answers, and three of five spoofable.
 *
 * Only the app knows how many proxies sit in front of it and which hop is the
 * client, so the app supplies the value:
 *
 * ```ts
 * // Behind exactly one trusted proxy that appends the peer address:
 * getEnvironment: (req) => ({ ...iamExtractEnvironment(req), ip: trustedClientIp(req) })
 * // Or, if you have already told your framework about your proxies:
 * getEnvironment: (req) => iamExtractEnvironment(req, { trustProxy: true })
 * ```
 *
 * `trustProxy` restores the old chain - `req.ip`, then the leftmost
 * `x-forwarded-for` hop, then `x-real-ip` - and is only safe when something in
 * front of the app overwrites those headers on every request.
 *
 * @param req - Provides any request-like object with `ip` and/or `headers`.
 * @param opts - Set `trustProxy` to read the forwarding headers. Off by default.
 * @returns The extracted {@link IamRequest.IEnvironment}.
 */
export function iamExtractEnvironment(
  req: {
    ip?: string
    headers?: Record<string, string | string[] | undefined> | Headers
    method?: string
    url?: string
  },
  opts?: { trustProxy?: boolean },
): IamRequest.IEnvironment {
  const getHeader = (name: string): string | undefined => {
    if (!req.headers) return undefined
    if (req.headers instanceof Headers) return req.headers.get(name) ?? undefined
    const val = req.headers[name]
    return Array.isArray(val) ? val[0] : val
  }

  return {
    // XFF can carry multiple comma-separated values (one per proxy hop,
    // leftmost is the original client). `req.ip` is read here too rather than
    // trusted on its own: an integration may fill it from a platform header
    // rather than a socket, and `env.ip` flows into `matches` conditions the
    // same way `userAgent` does.
    ip:
      opts?.trustProxy === true
        ? (normalizeForwardedFor(req.ip) ??
          normalizeForwardedFor(getHeader('x-forwarded-for')) ??
          normalizeForwardedFor(getHeader('x-real-ip')))
        : undefined,
    userAgent: normalizeUserAgent(getHeader('user-agent')),
    timestamp: Date.now(),
  }
}

/**
 * Drop an oversized `User-Agent`. It is attacker-controlled and flows into
 * `matches` conditions, which throw above `MAX_REGEX_INPUT_LENGTH`; an
 * uncapped value lets a caller perturb evaluation with one header.
 */
function normalizeUserAgent(raw: string | undefined): string | undefined {
  if (typeof raw !== 'string') return undefined
  return raw.length === 0 || raw.length > MAX_USER_AGENT_LENGTH ? undefined : raw
}

/** Longest `User-Agent` passed through to conditions; matches the `matches` operator's input cap. */
const MAX_USER_AGENT_LENGTH = 2048

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

/**
 * Action used when a request's method is not in {@link IAM_METHOD_ACTION_MAP}.
 * Not a real action: an unmapped method must be denied rather than inheriting
 * `read` and passing a read check. The denial is enforced by the engine, which
 * reserves this token - see {@link IAM_RESERVED_REFUSAL}. It is not enough for
 * the string to look unmatchable, because a `'*'` rule matches every string.
 */
export const IAM_UNKNOWN_ACTION: typeof IAM_RESERVED_REFUSAL = IAM_RESERVED_REFUSAL

/**
 * Default action for an HTTP method. Case-insensitive, because `delete` from a
 * hand-rolled client must not miss the map and fall through to `read`.
 */
export function iamActionForMethod(method: string | undefined): string {
  if (typeof method !== 'string') return IAM_UNKNOWN_ACTION
  return IAM_METHOD_ACTION_MAP[method.toUpperCase()] ?? IAM_UNKNOWN_ACTION
}

/**
 * Canonical pathname for prefix/regex matching. `new URL()` resolves dot
 * segments but leaves `//admin` and `/%61dmin` intact, either of which skips a
 * `/admin` rule while still routing to `/admin`. Decodes once (as routers do),
 * collapses slash runs, then re-resolves dot segments the decode may have
 * revealed. A malformed escape keeps the raw path rather than throwing.
 */
export function iamNormalizePathname(pathname: string): string {
  let decoded = pathname
  try {
    decoded = decodeURIComponent(pathname)
  } catch {
    // Malformed percent-escape: keep the raw form so matching still runs.
  }
  const collapsed = decoded.replace(/\/{2,}/g, '/')
  const out: string[] = []
  for (const segment of collapsed.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      out.pop()
      continue
    }
    out.push(segment)
  }
  const joined = `/${out.join('/')}`
  return joined !== '/' && collapsed.endsWith('/') ? `${joined}/` : joined
}

/**
 * Is this a usable subject id?
 *
 * `getUserId` is *typed* `string | null`, and every integration tested it with
 * `if (!userId)`, which lets `42`, `true`, `{}` and `[]` straight through to
 * `engine.can` - the check runs against a subject that is not an id, and the
 * error surfaces (if at all) several layers down as an engine complaint rather
 * than as the 401 it is. The extractor is consumer code reading a request body
 * or a JWT claim, so its return type is a promise, not a guarantee; this is
 * where the promise is checked.
 *
 * Blank is rejected for the same reason the empty string already was: a
 * whitespace id names no subject.
 */
export function iamIsSubjectId(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

/**
 * Resource type used when a request path cannot be trusted to name one.
 * Reserved by the engine, which refuses it before consulting any policy, so the
 * request is denied rather than authorized against whatever the raw path
 * happened to spell - see {@link IAM_RESERVED_REFUSAL}.
 */
export const IAM_UNKNOWN_RESOURCE: typeof IAM_RESERVED_REFUSAL = IAM_RESERVED_REFUSAL

/**
 * True when a raw path segment can be read one way here and another way by the
 * router that will serve the request.
 *
 * A traversal has no safe resolution at this layer. Resolving it is what
 * created the bypass: `/admin/../public` canonicalises to `/public`, so the
 * check was made about `public` and passed, and then express, hono and next
 * each routed the raw target to the `/admin` handler anyway - authorized as one
 * resource, served as another. Refusing to resolve is the only answer that does
 * not depend on guessing which framework's normalizer runs downstream.
 *
 * Legitimate escapes are left alone: only a segment that IS a dot-segment, or
 * decodes into one, into a separator, or into another escape, is ambiguous.
 * `/posts/hello%20world` is not.
 */
export function iamPathIsAmbiguous(raw: string): boolean {
  for (const segment of raw.split('/')) {
    if (segment === '.' || segment === '..') return true
    // A literal backslash, not only an encoded one. The WHATWG URL parser
    // rewrites `\` to `/` in a special-scheme URL *before* resolving dot
    // segments, so `new URL('http://x/posts\\..\\admin').pathname` is
    // `/admin`: this layer reads the type as `posts\..\admin` while anything
    // parsing the target through `URL` reads `/admin`. The decoded check below
    // already treats `\` as a separator, so `%5C` was refused while the plain
    // character - the easier one to send - was not.
    if (segment.includes('\\')) return true
    if (!segment.includes('%')) continue
    let decoded: string
    try {
      decoded = decodeURIComponent(segment)
    } catch {
      // A malformed escape is decoded by nobody here and by something
      // downstream - which is the definition of ambiguous.
      return true
    }
    if (decoded === '.' || decoded === '..') return true
    // `%` again means double-encoded: a router that decodes twice sees a
    // different path than a router that decodes once.
    if (/[/\\%\0]/.test(decoded)) return true
  }
  return false
}

/**
 * Default `{ type, id }` for a request path, shared by the framework adapters.
 *
 * The raw path is not usable here: `/posts/../admin/secret` reads as type
 * `posts`, so the check passes while the router serves `/admin/secret`. Nor is
 * the canonicalised path, which reads as `admin` here while express serves
 * `/posts`. Anything a router might resolve differently falls back to
 * {@link IAM_UNKNOWN_RESOURCE}, which the engine refuses outright - see
 * {@link IAM_RESERVED_REFUSAL}; being unmatchable by any policy is not
 * something a string can guarantee, because `'*'` matches strings.
 */
export function iamDefaultResource(pathname: string | undefined): {
  type: string
  id: string | undefined
  attributes: Record<string, never>
} {
  const raw = typeof pathname === 'string' ? pathname : '/'
  if (iamPathIsAmbiguous(raw)) {
    return { attributes: {}, id: undefined, type: IAM_UNKNOWN_RESOURCE }
  }
  const parts = iamNormalizePathname(raw).split('/').filter(Boolean)
  if (parts.some((segment) => segment.includes('%'))) {
    return { attributes: {}, id: undefined, type: IAM_UNKNOWN_RESOURCE }
  }
  return { attributes: {}, id: parts[1], type: parts[0] ?? 'root' }
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

/**
 * Reads a required string field out of an admin request body.
 *
 * The admin routers used to take `body.roleId as TRole` straight from the
 * parsed JSON. `assertTriple` inside the engine does catch a non-string and
 * throws, so nothing was writable that should not have been - but the cast put
 * a domain type on an unvalidated request field several calls before anything
 * looked at it, and read as though the check had already happened. This is
 * that check, at the edge, with a message naming the field.
 *
 * @param source - The parsed request body.
 * @param field - The field to read.
 * @returns The field's value, guaranteed a non-empty string.
 * @throws If the body is not an object, or the field is missing, not a string, or empty.
 */
export function iamRequireStringField(source: unknown, field: string): string {
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    throw new Error(`[@gentleduck/iam:generic] request body must be a JSON object to read "${field}"`)
  }
  const value: unknown = Reflect.get(source, field)
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`[@gentleduck/iam:generic] "${field}" must be a non-empty string`)
  }
  return value
}

/**
 * {@link iamRequireStringField} for a field that may be absent.
 *
 * An explicit `null` reads as absent - that is how a JSON client spells "no
 * scope" - but a present non-string is still an error rather than a silently
 * dropped scope, which would widen a scoped grant into a global one.
 *
 * @param source - The parsed request body.
 * @param field - The field to read.
 * @returns The value, or `undefined` when the field is absent or `null`.
 * @throws If the body is not an object, or the field is present but not a non-empty string.
 */
export function iamOptionalStringField(source: unknown, field: string): string | undefined {
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    throw new Error(`[@gentleduck/iam:generic] request body must be a JSON object to read "${field}"`)
  }
  const value: unknown = Reflect.get(source, field)
  if (value === undefined || value === null) return undefined
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`[@gentleduck/iam:generic] "${field}" must be a non-empty string when present`)
  }
  return value
}

/**
 * A required path parameter. Same reasoning as {@link iamRequireStringField}:
 * `req.params?.id as string` typed away the `undefined` that an unmatched route
 * actually produces.
 *
 * @param value - The raw parameter, as the framework hands it over.
 * @param name - The parameter's name, for the error message.
 * @returns The parameter, guaranteed a non-empty string.
 * @throws If it is absent or empty.
 */
export function iamRequirePathParam(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`[@gentleduck/iam:generic] path parameter "${name}" is missing`)
  }
  return value
}
