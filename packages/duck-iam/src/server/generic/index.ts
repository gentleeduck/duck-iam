import type { IamEngine } from '../../core'
import { fail, type IamError, throwIamError } from '../../core/errors'
import type { AccessControl, IamClient, IamPrimitives, IamRequest } from '../../core/types'
import { IAM_RESERVED_REFUSAL } from '../../shared/reserved'

/**
 * Audit types for the admin routers: `onAdminMutation` fires once per mutation (never on GET), on success or failure.
 * NOTE: the hook runs inline and is not awaited: its synchronous work delays the response, its errors never alter it.
 */
export namespace IamAdminAudit {
  /** Categorical action describing what changed. */
  export type Action = 'create' | 'update' | 'delete' | 'replace'
  /** Categorical target describing what kind of object was changed. */
  export type Target = 'policy' | 'role' | 'role-assignment'

  /** A single admin mutation event. */
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
     * Request path with route params expanded.
     * SECURITY: it may carry tenant or subject ids; strip them with {@link IOptions.redactPath}.
     */
    path: string
    /** Whether the handler completed without throwing or returning an HTTP refusal (>= 400). */
    success: boolean
    /**
     * Set when `success === false`: `HTTP <status>` for a returned refusal, else the thrown class name, or
     * `err.message` with {@link IOptions.includeErrorMessage}.
     */
    error?: string
  }

  /** Audit-hook signature. Sync or async; never awaited by the adapter. */
  export type Hook = (event: IEvent) => void | Promise<void>

  /** Audit-hook hardening options, composed into every adapter's admin-router options. All optional. */
  export interface IOptions {
    /**
     * Rewrites {@link IEvent.path} before the hook sees it; use it when the audit sink is outside your trust boundary.
     * If it throws, the hook is skipped and the error is reported like a hook error.
     *
     * @example
     * ```ts
     * // Replace the last segment with `:id`.
     * redactPath: (p) => p.replace(/\/[^/]+$/, '/:id')
     * ```
     */
    redactPath?: (path: string) => string
    /**
     * Receives errors the hook throws, sync or async; defaults to `console.error`.
     * Its own throws are logged to `console.error` and never propagate.
     */
    onAuditHookError?: (err: unknown, event: IEvent) => void
    /**
     * Puts `err.message` in {@link IEvent.error} instead of the class name.
     * SECURITY: DB-driver messages can carry credentials or SQL; enable only if you control the throw sites and sink.
     */
    includeErrorMessage?: boolean
    /**
     * CSRF guard for admin routes. Defaults to {@link iamDefaultCsrfCheck}; `false` disables it (bearer-token or mTLS
     * APIs), and a function replaces it, e.g. with an Origin allowlist.
     *
     * @example
     * ```ts
     * // Default - uses built-in Sec-Fetch-Site check
     * iamAdminRouter(engine, { authorize })
     *
     * // Disable (bearer-token API, no browser involved)
     * iamAdminRouter(engine, { authorize, csrfCheck: false })
     *
     * // Stricter: Origin allowlist
     * const ADMIN_ORIGINS = new Set(['https://admin.example.com'])
     * iamAdminRouter(engine, {
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
 * Logs, once per process, that the default CSRF check is on. Called by every admin router at construction; silent
 * when the operator passed any `csrfCheck`, including `false`.
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
 * Reads `Sec-Fetch-Site` from any of the three header shapes adapters pass.
 * SECURITY: case-insensitive, since a missed header reads as "not a browser" and is allowed.
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
 * Default admin CSRF check: refuses a request whose `Sec-Fetch-Site` is `cross-site` or `cross-origin`.
 * SECURITY: page script cannot forge the header; without it the caller is not a browser and is left to its own auth.
 *
 * @param req - The framework request, in any header shape {@link readSecFetchSite} reads.
 * @returns `true` when the request may proceed.
 */
export function iamDefaultCsrfCheck(req: unknown): boolean {
  const site = readSecFetchSite(req)
  if (!site) return true // non-browser caller; let bearer/mTLS auth decide
  return site !== 'cross-site' && site !== 'cross-origin'
}

/**
 * The `id` of a policy or role body, for an audit event's `targetId`; `undefined` unless it is a non-empty string.
 * NOTE: reads the raw parsed body, before validation, so a body without a usable id records no target.
 */
export function iamAuditIdOf(body: unknown): string | undefined {
  if (body === null || typeof body !== 'object') return undefined
  const id: unknown = Reflect.get(body, 'id')
  return typeof id === 'string' && id.length > 0 ? id : undefined
}

/**
 * Status of a returned HTTP refusal (>= 400), so a refused write is not audited as a success.
 * Duck-typed on `status` because `Response` classes differ across realms.
 */
function refusalStatus(value: unknown): number | undefined {
  if (value === null || typeof value !== 'object') return undefined
  const status: unknown = Reflect.get(value, 'status')
  if (typeof status !== 'number' || !Number.isFinite(status) || status < 400) return undefined
  return status
}

/**
 * Runs an admin mutation and fires its audit event in `finally`, re-throwing any error for the adapter to answer.
 * SECURITY: a handler that returns an HTTP refusal is audited as a failure, never as a change that happened.
 *
 * @template T - Handler return type.
 * @param ctx - Audit payload and hooks shared across framework adapters.
 * @param handler - The mutation itself, e.g. `engine.admin.savePolicy`.
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
    // Returning normally is not the same as succeeding - see `refusalStatus`.
    const refused = refusalStatus(out)
    success = refused === undefined
    if (refused !== undefined) errorMessage = `HTTP ${refused}`
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
 * A value that names who made an admin mutation: a non-empty string (subject id) or an identifying object.
 * NOTE: an array satisfies this type but names no one, so {@link iamIsNameableActor} refuses it at runtime.
 */
export type IamAdminActor = string | object

/**
 * What admin `authorize` may return: an {@link IamAdminActor}, `true` (allowed, no actor), or a falsy refusal.
 * NOTE: not `unknown`: a number is truthy but names no one, so it would authorize and lose the attribution.
 */
export type IamAdminAuthzAnswer = IamAdminActor | boolean | null | undefined

/** The CSRF check refused the request, or threw. */
export interface IamIAdminAuthzForbidden {
  phase: 'forbidden'
}

/** The caller is not an admin: `authorize` returned false or a falsy actor. */
export interface IamIAdminAuthzUnauthorized {
  phase: 'unauthorized'
}

/** `authorize` threw. Kept apart from `unauthorized` so a broken callback reports as a server fault, not a denial. */
export interface IamIAdminAuthzError {
  phase: 'error'
  error: Error
}

/**
 * The caller may proceed. `actor` is what `authorize` returned, or `undefined` when that names no one (e.g. `true`).
 */
export interface IamIAdminAuthzOk {
  phase: 'ok'
  actor: IamAdminActor | undefined
}

/** Every outcome of the shared admin gate. Exhaustive: adapters switch on `phase`. */
export type IamIAdminAuthzResult =
  | IamIAdminAuthzForbidden
  | IamIAdminAuthzUnauthorized
  | IamIAdminAuthzError
  | IamIAdminAuthzOk

/** Runs the CSRF and authorize phases shared by every admin route; each adapter maps the result to its own response. */
export async function iamRunAdminAuthz<TReq>(
  req: TReq,
  csrfCheck: ((req: TReq) => boolean) | null,
  // NOTE: not `unknown | Promise<unknown>`, which collapses to `unknown` and types nothing.
  authorize: (req: TReq) => IamAdminAuthzAnswer | Promise<IamAdminAuthzAnswer>,
): Promise<IamIAdminAuthzResult> {
  if (csrfCheck) {
    // SECURITY: a predicate that throws has not said yes, so it refuses.
    let passed: boolean
    try {
      passed = csrfCheck(req)
    } catch {
      return { phase: 'forbidden' }
    }
    if (!passed) return { phase: 'forbidden' }
  }
  let actor: IamAdminAuthzAnswer
  try {
    actor = await authorize(req)
  } catch (err) {
    return { phase: 'error', error: err instanceof Error ? err : new Error(String(err)) }
  }
  if (!actor) return { phase: 'unauthorized' }
  // Any truthy answer authorizes, but only a value that names someone is recorded as the actor.
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
 * The `actor` an admin router hands `engine.admin.*`, so an HTTP write reaches the adapter's provenance columns.
 * The engine's actor is a string, so a string actor names the caller and anything else names no one unless `map`
 * resolves it.
 *
 * @param actor - What `authorize` returned, as {@link iamRunAdminAuthz} resolved it.
 * @param map - `getMutationActor`: picks the naming field out of an object actor.
 */
export function iamAdminActorOptions(
  actor: IamAdminActor | undefined,
  map?: (actor: IamAdminActor) => string | undefined,
): { actor?: string } {
  if (actor === undefined) return {}
  const named = map ? map(actor) : typeof actor === 'string' ? actor : undefined
  return typeof named === 'string' && named.trim().length > 0 ? { actor: named } : {}
}

/**
 * Whether a value can be recorded as an admin mutation's actor: a non-blank string or a non-array object.
 * The admin-path counterpart of {@link iamIsSubjectId}.
 */
export function iamIsNameableActor(value: unknown): value is IamAdminActor {
  if (typeof value === 'string') return value.trim().length > 0
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Audit string for a thrown value: its class name, or with `includeMessage` its message (non-Errors tagged and capped).
 * SECURITY: the class-name default keeps credentials and SQL from driver messages out of audit sinks.
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

/** `JSON.stringify` for detail, falling back to `String()` for circular or unserialisable values. */
function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? String(v)
  } catch {
    return String(v)
  }
}

/**
 * Calls an {@link IamAdminAudit.Hook} inline without awaiting it (a no-op without one); its errors never propagate.
 * SECURITY: `redactPath` runs first, and if it throws the hook is skipped, so an unredacted path never reaches it.
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

/** Sends a hook failure to `onAuditHookError`, else `console.error`; a throwing sink falls back to `console.error`. */
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
 * Builds a server-side permission map for a subject; call once per request and forward the map to the client.
 *
 * @template TAction - Valid action strings.
 * @template TResource - Valid resource strings.
 * @template TRole - Valid role strings.
 * @template TScope - Valid scope strings.
 * @template TMode - Inferred from `engine`: a typed {@link IamClient.PermissionMap} in development, plain otherwise.
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
 * Builds a typed `(action, resourceType, resourceId?, scope?) => Promise<boolean>` checker bound to one subject.
 *
 * SECURITY: a rule reading `resource.attributes.*` sees only the attributes passed to the returned checker;
 * without them the resource is a type and an id, and such a rule cannot fire.
 *
 * @template TAction - Valid action strings.
 * @template TResource - Valid resource strings.
 * @template TRole - Valid role strings.
 * @template TScope - Valid scope strings.
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
  return (
    action: TAction,
    resourceType: TResource,
    resourceId?: string,
    scope?: TScope,
    attributes?: Readonly<IamPrimitives.Attributes>,
  ) =>
    engine.can(
      subjectId,
      action,
      { type: resourceType, id: resourceId, attributes: attributes ?? {} },
      environment,
      scope,
    )
}

/**
 * Extracts `{ ip, userAgent, timestamp }` from common request shapes.
 * SECURITY: `ip` is `undefined` without `trustProxy`; forwarding headers are client-set unless a proxy overwrites them.
 *
 * @param req - Any request-like object with `ip` and/or `headers`.
 * @param opts - `trustProxy` reads `req.ip`, then the leftmost `x-forwarded-for` hop, then `x-real-ip`. Off by default.
 * @example
 * ```ts
 * // Behind exactly one trusted proxy that appends the peer address:
 * getEnvironment: (req) => ({ ...iamExtractEnvironment(req), ip: trustedClientIp(req) })
 * // Or, if you have already told your framework about your proxies:
 * getEnvironment: (req) => iamExtractEnvironment(req, { trustProxy: true })
 * ```
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
    // The leftmost XFF hop is the original client. `req.ip` is normalised too: an integration may fill it from a
    // platform header, and `ip` flows into `matches` conditions.
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
 * Drops an empty or oversized `User-Agent`.
 * SECURITY: it is client-set and `matches` conditions throw above `MAX_REGEX_INPUT_LENGTH`.
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
 * Action for a method missing from {@link IAM_METHOD_ACTION_MAP}, so it is denied rather than treated as `read`.
 * SECURITY: the engine refuses this reserved token outright; see {@link IAM_RESERVED_REFUSAL}.
 */
export const IAM_UNKNOWN_ACTION: typeof IAM_RESERVED_REFUSAL = IAM_RESERVED_REFUSAL

/** Default action for an HTTP method, matched case-insensitively; an unmapped one gets {@link IAM_UNKNOWN_ACTION}. */
export function iamActionForMethod(method: string | undefined): string {
  if (typeof method !== 'string') return IAM_UNKNOWN_ACTION
  return IAM_METHOD_ACTION_MAP[method.toUpperCase()] ?? IAM_UNKNOWN_ACTION
}

/**
 * Canonical pathname for prefix/regex matching: decodes once, as routers do, then collapses slashes and dot segments.
 * SECURITY: `new URL()` leaves `//admin` and `/%61dmin` intact, either of which would skip an `/admin` rule.
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
 * Whether `getUserId` returned a usable subject id: a non-blank string.
 * NOTE: checked at runtime because the extractor is consumer code; a truthiness test would pass `42` or `{}` on.
 */
export function iamIsSubjectId(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

/**
 * Resource type for a request path that cannot be trusted to name one.
 * SECURITY: the engine refuses this reserved token before any policy; see {@link IAM_RESERVED_REFUSAL}.
 */
export const IAM_UNKNOWN_RESOURCE: typeof IAM_RESERVED_REFUSAL = IAM_RESERVED_REFUSAL

/**
 * True when a raw path segment could be read one way here and another way by the router serving the request.
 * SECURITY: traversals are refused, not resolved: `/admin/../public` is checked as `public` but routed to `/admin`.
 */
export function iamPathIsAmbiguous(raw: string): boolean {
  for (const segment of raw.split('/')) {
    if (segment === '.' || segment === '..') return true
    // INFO: a literal `\` too: the WHATWG URL parser turns it into `/` before resolving dot segments.
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
 * SECURITY: an ambiguous or still-encoded path gets {@link IAM_UNKNOWN_RESOURCE}, which the engine refuses outright.
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
 * The longest an admin-supplied id may be.
 * NOTE: matches the engine's cap (`assertNonEmptyStringParam`), so the edge never refuses an id the engine accepts.
 */
export const IAM_MAX_ADMIN_FIELD_LENGTH = 1024

function assertJsonObjectBody(source: unknown, field: string): asserts source is object {
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    throw fieldError('NOT_AN_OBJECT', field, 'cannot be read: the request body is not a JSON object')
  }
}

/**
 * The one place an admin-supplied id is checked: non-empty, non-blank, within {@link IAM_MAX_ADMIN_FIELD_LENGTH}.
 * NOTE: blank is refused, not trimmed; trimming would grant on an id the caller did not send.
 */
function assertFieldString(value: unknown, field: string, hint?: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw fieldError('INVALID_FIELD', field, 'must be a non-empty string', hint)
  }
  if (value.trim().length === 0) {
    throw fieldError('BLANK_FIELD', field, 'must not be blank', hint)
  }
  if (value.length > IAM_MAX_ADMIN_FIELD_LENGTH) {
    throw fieldError('FIELD_TOO_LONG', field, `exceeds the ${IAM_MAX_ADMIN_FIELD_LENGTH}-char cap`, hint)
  }
  return value
}

/**
 * Builds the refusal for one bad request field.
 * NOTE: `issues` repeats the full explanation because it is the only part the adapters put in the response body.
 */
function fieldError(code: string, field: string, detail: string, hint?: string): IamError {
  const tail = hint === undefined ? '' : `; ${hint}`
  return fail('IAM_VALIDATION_FAILED', {
    kind: 'request',
    issues: [`${code} at "${field}": ${detail}${tail}`],
  })
}

/**
 * Parses an admin request body, turning malformed JSON into a 400 as the express and nest hosts already do.
 *
 * @param read - The framework's own parse call, e.g. `() => c.req.json()`.
 * @throws {IamError} When the body is not valid JSON.
 */
export async function iamReadJsonBody(read: () => Promise<unknown>): Promise<unknown> {
  try {
    return await read()
  } catch {
    // SECURITY: the parser's message quotes caller-controlled bytes, so it stays out of operator logs.
    throwIamError('IAM_VALIDATION_FAILED', { kind: 'request', issues: ['MALFORMED_JSON'] })
  }
}

/**
 * Reads a required string field from an admin request body, checked at the edge with a message naming the field.
 *
 * @returns The field's value, guaranteed a non-blank string.
 * @throws {IamError} If the body is not an object, or the field is missing, not a string, blank, or too long.
 */
export function iamRequireStringField(source: unknown, field: string): string {
  assertJsonObjectBody(source, field)
  return assertFieldString(Reflect.get(source, field), field)
}

/**
 * {@link iamRequireStringField} for a field that may be absent; omitting it is how a caller says "unset".
 * SECURITY: an explicit `null` is refused, not read as absent, since a `null` grant scope would widen to global.
 *
 * @returns The value, or `undefined` when the field is absent.
 * @throws {IamError} If the body is not an object, or the field is present and not a valid string.
 */
export function iamOptionalStringField(source: unknown, field: string): string | undefined {
  assertJsonObjectBody(source, field)
  const value: unknown = Reflect.get(source, field)
  if (value === undefined) return undefined
  return assertFieldString(value, field, 'omit the field entirely to mean "unset"')
}

/**
 * A required path parameter, checked like {@link iamRequireStringField}; an unmatched route yields `undefined`.
 *
 * @param value - The raw parameter, as the framework hands it over.
 * @param name - The parameter's name, for the error message.
 * @throws {IamError} If it is absent, blank, or too long.
 */
export function iamRequirePathParam(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw fieldError('MISSING_PARAM', name, 'is a required path parameter and is missing')
  }
  if (value.trim().length === 0) {
    throw fieldError('BLANK_PARAM', name, 'is a path parameter and must not be blank')
  }
  if (value.length > IAM_MAX_ADMIN_FIELD_LENGTH) {
    throw fieldError('PARAM_TOO_LONG', name, `exceeds the ${IAM_MAX_ADMIN_FIELD_LENGTH}-char cap`)
  }
  return value
}
