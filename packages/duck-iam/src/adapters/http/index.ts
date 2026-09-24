import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import {
  iamAssertSavablePolicy,
  iamAssertSavableRole,
  iamNormalizePolicy,
  iamUnreadablePolicy,
  iamUnreadableRole,
} from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'

/** Brand symbol marking an error as retry-eligible. Internal to this adapter. */
const TRANSIENT = Symbol('duck-iam.http.transient')

/** Tags an Error as transient so `isTransientError` will pick it up. Returns the same instance. */
function makeTransient<T extends Error>(err: T): T {
  Reflect.set(err, TRANSIENT, true)
  return err
}

/**
 * True if the error should be retried: tagged {@link TRANSIENT}, a fetch `AbortError`/`TypeError`,
 * or a Node socket code (`ECONNRESET`, `ECONNREFUSED`, `ETIMEDOUT`, `ENOTFOUND`).
 */
function isTransientError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false
  if (Reflect.get(err, TRANSIENT) === true) return true
  const name = Reflect.get(err, 'name')
  if (name === 'AbortError' || name === 'TypeError') return true
  const code = Reflect.get(err, 'code')
  return code === 'ECONNRESET' || code === 'ECONNREFUSED' || code === 'ETIMEDOUT' || code === 'ENOTFOUND'
}

/** Combines AbortSignals into one that aborts when any does (request timeout, engine timeout, caller signal). */
function anySignal(signals: AbortSignal[]): AbortSignal | undefined {
  if (signals.length === 0) return undefined
  if (signals.length === 1) return signals[0]
  const ctrl = new AbortController()
  const onAbort = (reason: unknown) => ctrl.abort(reason)
  for (const sig of signals) {
    if (sig.aborted) {
      ctrl.abort(sig.reason)
      break
    }
    sig.addEventListener('abort', () => onAbort(sig.reason), { once: true })
  }
  return ctrl.signal
}
/** HTTP adapter integration types. Type-only namespace - zero bundle cost. */
export namespace IamHttp {
  /** Configuration for {@link IamHttpAdapter}: endpoint, fetch overrides, retry, and circuit-breaker tuning. */
  export interface IConfig {
    /** Specifies the base URL of the duck-iam API (e.g. `https://api.example.com/access`). */
    baseUrl: string
    /**
     * Called when an API row fails validation, just before the read throws.
     * SECURITY: rows fail closed - a dropped policy could be the one that denies, and a dropped role is what a
     * deny selects on, so neither is skipped.
     */
    onPolicyError?: IamAdapter.RowErrorHandler<'http'>
    /** Overrides the default `globalThis.fetch` implementation. */
    fetch?: typeof globalThis.fetch
    /** Provides headers (e.g. auth tokens) merged into every request. */
    headers?: Record<string, string> | (() => Record<string, string> | Promise<Record<string, string>>)
    /**
     * Per-request timeout in ms, layered with the engine's `adapterTimeoutMs` (first to fire wins).
     * Defaults to `5_000`; `0` relies on the engine timeout alone.
     */
    timeoutMs?: number
    /** Retry attempts on transient failures (5xx, network errors, timeouts); 4xx is never retried. Defaults to `2`. */
    retries?: number
    /** Base backoff in ms: retry N waits `backoffMs * 2^(N-1)` (capped at 60 s) plus jitter. Defaults to `100`. */
    backoffMs?: number
    /**
     * Opens the circuit after this many consecutive failed requests; while open, requests reject until the cooldown.
     * SECURITY: an integer >= 1 (default `5`); `0` is refused at construction, so a bad env value cannot disable it.
     */
    circuitBreakerThreshold?: number
    /** Cooldown in ms before one half-open probe goes through; success closes, failure re-opens. Default `30_000`. */
    circuitBreakerCooldownMs?: number
    /**
     * Allowed `baseUrl` hosts, case-insensitive: a bare host matches any port, `host:port` only that port.
     * SECURITY: SSRF defence in depth; construction throws on a mismatch, and omitting it logs a one-time warning.
     */
    allowedHosts?: string[]
    /**
     * Permits a `baseUrl` that is a private, loopback, or link-local IP literal. Defaults to `false`.
     * INFO: DNS names are not resolved (that would need sync I/O), so only `allowedHosts` constrains them.
     */
    allowPrivateHosts?: boolean
  }
}

/** One-time latch for the omitted-`allowedHosts` warning; module-level so repeated constructions do not spam. */
const _ALLOWED_HOSTS_WARNED = { fired: false }

/** Converts a two-group hex IPv4 tail (`7f00:1`) to dotted-quad (`127.0.0.1`), or `null` if malformed. */
function _hexTailToDottedQuad(tail: string): string | null {
  const m = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail)
  if (!m || m[1] === undefined || m[2] === undefined) return null
  const hi = parseInt(m[1], 16)
  const lo = parseInt(m[2], 16)
  if (!Number.isFinite(hi) || !Number.isFinite(lo)) return null
  if (hi < 0 || hi > 0xffff || lo < 0 || lo > 0xffff) return null
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`
}

/**
 * True for an IP literal in a private, loopback, link-local, or unique-local range; DNS names return `false`.
 * SECURITY: unwraps IPv4 embedded in IPv6 (mapped, compatible, 6to4, NAT64) so those forms cannot bypass it.
 */
function _isPrivateHost(hostname: string): boolean {
  // Strip IPv6 brackets and one trailing FQDN dot, so `127.0.0.1.` is checked as `127.0.0.1`.
  let h = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname
  if (h.endsWith('.')) h = h.slice(0, -1)
  // IPv4 dotted-quad
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (v4) {
    const a = Number(v4[1])
    const b = Number(v4[2])
    if (a === 127) return true // loopback
    if (a === 10) return true // RFC1918
    if (a === 192 && b === 168) return true // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true // RFC1918
    if (a === 169 && b === 254) return true // link-local
    if (a === 0) return true // "this network" - includes 0.0.0.0 unspecified
    return false
  }
  // IPv6 literal
  if (h.includes(':')) {
    const lower = h.toLowerCase()
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true
    // Unspecified `::` often reaches a local interface; block its expanded form too.
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true
    // fc00::/7 - first byte 0xfc or 0xfd
    if (/^f[cd][0-9a-f]{0,2}:/.test(lower)) return true
    // fe80::/10 - fe8x, fe9x, feax, febx
    if (/^fe[89ab][0-9a-f]?:/.test(lower)) return true
    // IPv4-mapped: `::ffff:a.b.c.d`, the `::ffff:hhhh:hhhh` form Node's URL parser emits, or `0:0:0:0:0:ffff:...`.
    let mappedTail: string | null = null
    if (lower.startsWith('::ffff:')) mappedTail = lower.slice(7)
    else if (lower.startsWith('0:0:0:0:0:ffff:')) mappedTail = lower.slice(15)
    if (mappedTail !== null) {
      // Dotted-quad tail (`::ffff:127.0.0.1`).
      if (mappedTail.includes('.')) return _isPrivateHost(mappedTail)
      // Hex tail (`::ffff:7f00:1`) - convert to dotted-quad then re-check.
      const dotted = _hexTailToDottedQuad(mappedTail)
      if (dotted) return _isPrivateHost(dotted)
      return false
    }
    // IPv4-compatible `::a.b.c.d` (deprecated, RFC 4291 2.5.5.1); Node emits hex, but cover the textual form.
    if (lower.startsWith('::') && lower.includes('.')) {
      const tail = lower.slice(2)
      if (/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(tail)) return _isPrivateHost(tail)
    }
    // 6to4 `2002::/16` embeds an IPv4 in the next two groups: `2002:7f00:1::` carries `127.0.0.1`.
    if (lower.startsWith('2002:')) {
      const m = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?::|$)/.exec(lower)
      if (m) {
        const dotted = _hexTailToDottedQuad(`${m[1]}:${m[2]}`)
        if (dotted) return _isPrivateHost(dotted)
      }
    }
    // NAT64 `64:ff9b::/96`; accept both canonical and `0064:ff9b:` spellings.
    if (lower.startsWith('64:ff9b:') || lower.startsWith('0064:ff9b:')) {
      const tail = lower.startsWith('0064:') ? lower.slice(10) : lower.slice(8)
      // Dotted-quad tail (`64:ff9b::127.0.0.1`).
      if (tail.includes('.')) {
        const v4match = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(tail)
        if (v4match?.[1]) return _isPrivateHost(v4match[1])
      }
      // Hex tail - last two non-empty hex groups form the 32-bit v4.
      const groups = tail.split(':').filter((g) => g.length > 0)
      if (groups.length >= 2) {
        const dotted = _hexTailToDottedQuad(`${groups[groups.length - 2]}:${groups[groups.length - 1]}`)
        if (dotted) return _isPrivateHost(dotted)
      }
    }
    return false
  }
  return false
}

/** Lowercase, strip trailing FQDN dot, IDN -> punycode via `new URL`; invalid input falls back to lowercased input. */
function _normaliseHostForAllowlist(host: string): string {
  let h = host.toLowerCase()
  if (h.endsWith('.')) h = h.slice(0, -1)
  // Fast path: pure ASCII needs no IDN conversion.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: explicit ASCII range check.
  if (/^[\x00-\x7f]*$/.test(h)) return h
  try {
    return new URL(`http://${h}`).hostname
  } catch {
    return h
  }
}

/** Longest id this adapter puts in a URL path; past this a server is more likely to truncate or reject than serve. */
const MAX_ID_LENGTH = 1024

/**
 * One URL path segment from an id; reads and writes share it, so a write cannot store an id no read can fetch.
 * SECURITY: separators and all-dot segments are refused, not encoded, since some servers decode `%2F` before routing.
 */
function segment(value: string, field: string): string {
  if (typeof value !== 'string' || value === '') {
    throw new Error(`[@gentleduck/iam:http] ${field} must be a non-empty string`)
  }
  if (value.includes('/') || value.includes('\\')) {
    throw new Error(`[@gentleduck/iam:http] ${field} cannot contain a path separator`)
  }
  if (/^\.+$/.test(value)) {
    throw new Error(`[@gentleduck/iam:http] ${field} cannot be a path segment of "${value}"`)
  }
  if (value.length > MAX_ID_LENGTH) {
    throw new Error(
      `[@gentleduck/iam:http] ${field} is ${value.length} characters, over the ${MAX_ID_LENGTH} this adapter will put in a URL path`,
    )
  }
  return encodeURIComponent(value)
}

/** Rejects an id the read path could never fetch back; `savePolicy`/`saveRole` send it in the body, not the path. */
function assertReadableId(id: unknown, field: string): void {
  if (typeof id !== 'string') {
    throw new Error(`[@gentleduck/iam:http] ${field} must be a non-empty string`)
  }
  segment(id, field)
}

/** Best-effort row id for error context: the row's own string `id`, else the caller's fallback. */
function rowIdOf(row: unknown, fallback: string): string {
  return typeof row === 'object' && row !== null && 'id' in row && typeof row.id === 'string' ? row.id : fallback
}

/**
 * The only request fields {@link IamHttpAdapter} sets; see `_request`.
 * NOTE: narrower than `RequestInit` on purpose: spreading a `Headers` instance yields `{}` and would drop auth headers.
 */
interface IHttpInit {
  readonly method?: string
  readonly body?: string
}

/**
 * Backs the access store with a remote HTTP API, adding per-request timeout, backoff retry, and a circuit breaker.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @example
 * ```ts
 * const adapter = new IamHttpAdapter({
 *   baseUrl: 'https://api.example.com/access',
 *   headers: { Authorization: 'Bearer ...' },
 * })
 * ```
 */
export class IamHttpAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _baseUrl: string
  private _fetch: typeof globalThis.fetch
  private _headers: IamHttp.IConfig['headers']
  private _timeoutMs: number
  private _retries: number
  private _backoffMs: number
  private _cbThreshold: number
  private _cbCooldownMs: number
  private _onPolicyError: IamHttp.IConfig['onPolicyError']
  // Circuit-breaker state. closed -> too many transients -> open -> cooldown
  // expires -> half-open -> success closes / failure re-opens.
  private _cbConsecutiveFailures = 0
  private _cbOpenedAt: number | null = null
  private _cbHalfOpenInFlight = false

  /** Creates a new HTTP adapter; throws on an invalid `baseUrl` or tuning option. */
  constructor(config: IamHttp.IConfig) {
    this._baseUrl = IamHttpAdapter._validateBaseUrl(config)
    this._fetch = config.fetch ?? globalThis.fetch.bind(globalThis)
    this._headers = config.headers
    this._timeoutMs = IamHttpAdapter._number('timeoutMs', config.timeoutMs, 5_000, { min: 0 })
    this._retries = IamHttpAdapter._number('retries', config.retries, 2, { integer: true, min: 0 })
    this._backoffMs = IamHttpAdapter._number('backoffMs', config.backoffMs, 100, { min: 0 })
    // NOTE: `min: 1` refuses a value that would disable the breaker; the `<= 0` branches in `_circuitState` and
    // `_onCircuitFailure` are unreachable through config, not a supported off switch.
    this._cbThreshold = IamHttpAdapter._number('circuitBreakerThreshold', config.circuitBreakerThreshold, 5, {
      integer: true,
      min: 1,
    })
    this._cbCooldownMs = IamHttpAdapter._number('circuitBreakerCooldownMs', config.circuitBreakerCooldownMs, 30_000, {
      min: 0,
    })
    this._onPolicyError = config.onPolicyError
  }

  /**
   * Reads a numeric option: `undefined` takes `fallback`; otherwise it must be finite, >= `min`, and integral if asked.
   * SECURITY: `retries: NaN` would send no request and `timeoutMs: NaN` would abort every one, so both throw here.
   */
  private static _number(
    name: string,
    value: number | undefined,
    fallback: number,
    bounds: { min: number; integer?: boolean },
  ): number {
    if (value === undefined) return fallback
    const ok =
      typeof value === 'number' &&
      Number.isFinite(value) &&
      value >= bounds.min &&
      (bounds.integer !== true || Number.isInteger(value))
    if (!ok) {
      throw new Error(
        `[@gentleduck/iam:http] \`${name}\` must be a finite ${bounds.integer === true ? 'integer' : 'number'} >= ${bounds.min}, got ${JSON.stringify(value)}`,
      )
    }
    return value
  }

  /**
   * Validates `baseUrl` and returns it as given, minus one trailing `/`.
   * SECURITY: http(s) only, no query or fragment, host in `allowedHosts`, and no private IP unless allowed.
   */
  private static _validateBaseUrl(config: IamHttp.IConfig): string {
    let parsed: URL
    try {
      parsed = new URL(config.baseUrl)
    } catch {
      throw new Error(`[@gentleduck/iam:http] invalid baseUrl ${JSON.stringify(config.baseUrl)}`)
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`[@gentleduck/iam:http] baseUrl scheme must be http: or https:, got ${parsed.protocol}`)
    }
    if (parsed.search || parsed.hash) {
      throw new Error('[@gentleduck/iam:http] baseUrl must not contain a query string or fragment')
    }
    if (config.allowedHosts && config.allowedHosts.length > 0) {
      // Two arms: bare hostname (any port) vs `hostname:port` (exact match).
      // Both sides normalised: lower-case, no FQDN trailing dot, IDN punycoded.
      const urlHostname = _normaliseHostForAllowlist(parsed.hostname)
      // For host (with port) we split, normalise host, then re-attach port.
      const rawHost = parsed.host.toLowerCase()
      const colonIdx = rawHost.lastIndexOf(':')
      const urlHost =
        colonIdx > 0 && !rawHost.startsWith('[')
          ? `${_normaliseHostForAllowlist(rawHost.slice(0, colonIdx))}:${rawHost.slice(colonIdx + 1)}`
          : _normaliseHostForAllowlist(rawHost)
      const normEntries = config.allowedHosts.map((h) => {
        const lower = h.toLowerCase()
        const ci = lower.lastIndexOf(':')
        if (ci > 0 && !lower.startsWith('[') && /^\d+$/.test(lower.slice(ci + 1))) {
          return `${_normaliseHostForAllowlist(lower.slice(0, ci))}:${lower.slice(ci + 1)}`
        }
        return _normaliseHostForAllowlist(lower)
      })
      const matched = normEntries.some((entry) => entry === urlHostname || entry === urlHost)
      if (!matched) {
        throw new Error(`[@gentleduck/iam:http] baseUrl host ${JSON.stringify(parsed.host)} not in allowedHosts`)
      }
    } else if (!_ALLOWED_HOSTS_WARNED.fired) {
      _ALLOWED_HOSTS_WARNED.fired = true
      console.warn(
        '[@gentleduck/iam:http] `allowedHosts` not set - any host accepted. Pass `init.allowedHosts` for SSRF defense in depth.',
      )
    }
    if (!config.allowPrivateHosts && _isPrivateHost(parsed.hostname)) {
      throw new Error(
        `[@gentleduck/iam:http] baseUrl host ${JSON.stringify(parsed.hostname)} resolves to a private/loopback range - set allowPrivateHosts: true to opt in`,
      )
    }
    return config.baseUrl.replace(/\/$/, '')
  }

  /**
   * Breaker state: closed passes, open rejects until the cooldown elapses, half-open allows one probe at a time.
   * `_fetchWithRetry` enforces it; the probe's outcome closes or re-opens the circuit.
   */
  private _circuitState(): 'closed' | 'open' | 'half-open' {
    if (this._cbThreshold <= 0 || this._cbOpenedAt === null) return 'closed'
    return Date.now() - this._cbOpenedAt < this._cbCooldownMs ? 'open' : 'half-open'
  }

  private _onCircuitSuccess(): void {
    this._cbConsecutiveFailures = 0
    this._cbOpenedAt = null
    this._cbHalfOpenInFlight = false
  }

  private _onCircuitFailure(): void {
    this._cbConsecutiveFailures++
    this._cbHalfOpenInFlight = false
    if (this._cbThreshold > 0 && this._cbConsecutiveFailures >= this._cbThreshold) {
      this._cbOpenedAt = Date.now()
    }
  }

  /** Fetches with retry and returns the capped JSON body; a non-2xx response throws. */
  private async _request(path: string, init?: IHttpInit, readOpts?: IamAdapter.IReadOptions): Promise<unknown> {
    const res = await this._fetchWithRetry(path, init, readOpts)
    if (!res.ok) {
      throw new Error(`[@gentleduck/iam:http] HTTP ${res.status}: ${await readBodyCapped(res)}`)
    }
    return readJsonCapped(res)
  }

  /** Routes a bad row to `onPolicyError`, or warns when no handler is set, so it never vanishes unseen. */
  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'http', rowId })
      return
    }
    console.warn(`[@gentleduck/iam:http] dropped malformed row "${rowId}": ${err.message}`)
  }

  /**
   * Narrows one API row to a policy.
   * SECURITY: a mismatch is reported and throws, never dropped or returned raw; see {@link iamUnreadablePolicy}.
   */
  private _narrowPolicy(row: unknown, fallbackId: string): AccessControl.IPolicy<TAction, TResource, TRole> | null {
    const policy = parsePolicyRow<TAction, TResource, TRole>(row)
    if (policy !== null) return policy
    const rowId = rowIdOf(row, fallbackId)
    const issues = validatePolicy(row)
      .issues.map((i) => i.message)
      .join('; ')
    this._reportPolicyError(new Error(`Invalid policy "${rowId}": ${issues}`), rowId)
    throw iamUnreadablePolicy('http', rowId, issues)
  }

  private _narrowRole(row: unknown, fallbackId: string): AccessControl.IRole<TAction, TResource, TRole, TScope> | null {
    const role = parseRoleRow<TAction, TResource, TRole, TScope>(row)
    if (role !== null) return role
    const rowId = rowIdOf(row, fallbackId)
    const issues = validateRole(row)
      .issues.map((i) => i.message)
      .join('; ')
    this._reportPolicyError(new Error(`Invalid role "${rowId}": ${issues}`), rowId)
    throw iamUnreadableRole('http', rowId, issues)
  }

  /** A list endpoint must return an array; anything else is dropped wholesale and reported once. */
  private _narrowList<T>(body: unknown, path: string, narrow: (row: unknown, fallbackId: string) => T | null): T[] {
    if (!Array.isArray(body)) {
      const got = body === null ? 'null' : typeof body
      this._reportPolicyError(new Error(`Expected an array from ${path}, got ${got}`), path)
      return []
    }
    const out: T[] = []
    for (const [i, row] of body.entries()) {
      const v = narrow(row, `${path}[${i}]`)
      if (v !== null) out.push(v)
    }
    return out
  }

  /** Like {@link IamHttpAdapter._request}, but a 404 returns `null`, per the "row or null" contract of `getPolicy`/`getRole`. */
  private async _requestOrNull(path: string, init?: IHttpInit, readOpts?: IamAdapter.IReadOptions): Promise<unknown> {
    const res = await this._fetchWithRetry(path, init, readOpts)
    if (res.status === 404) return null
    if (!res.ok) {
      throw new Error(`[@gentleduck/iam:http] HTTP ${res.status}: ${await readBodyCapped(res)}`)
    }
    // A bodiless success means no row, the same answer as a 404.
    return (await readJsonCapped(res)) ?? null
  }

  /**
   * Fetches through the circuit breaker, retrying transient failures (5xx, network, timeout) with backoff.
   * 4xx is a definitive answer and is returned without retry.
   */
  private async _fetchWithRetry(
    path: string,
    init: IHttpInit | undefined,
    readOpts?: IamAdapter.IReadOptions,
  ): Promise<Response> {
    const state = this._circuitState()
    if (state === 'open') {
      throw new Error('[@gentleduck/iam:http] circuit open - refusing request')
    }
    if (state === 'half-open') {
      if (this._cbHalfOpenInFlight) {
        throw new Error('[@gentleduck/iam:http] circuit half-open probe in flight')
      }
      this._cbHalfOpenInFlight = true
    }

    let attempt = 0
    let lastError: unknown
    while (attempt <= this._retries) {
      try {
        const res = await this._fetchOnce(path, init, readOpts)
        this._onCircuitSuccess()
        return res
      } catch (err) {
        lastError = err
        if (!isTransientError(err) || attempt === this._retries) {
          this._onCircuitFailure()
          throw err
        }
        // Cap the backoff so a large `_retries` cannot push the delay past setTimeout's 2^31 ms limit.
        const exp = Math.min(this._backoffMs * 2 ** attempt, 60_000)
        const delay = exp + Math.floor(Math.random() * Math.min(this._backoffMs, 5000))
        await new Promise((r) => setTimeout(r, delay))
        attempt++
      }
    }
    this._onCircuitFailure()
    // Reachable only if the loop never ran, which `_number` prevents; still never throw an unassigned `lastError`.
    if (lastError instanceof Error) throw lastError
    throw new Error(`[@gentleduck/iam:http] request to ${path} failed and no error was recorded`, { cause: lastError })
  }

  private async _fetchOnce(
    path: string,
    init: IHttpInit | undefined,
    readOpts?: IamAdapter.IReadOptions,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(typeof this._headers === 'function' ? await this._headers() : (this._headers ?? {})),
    }
    const timeout = this._timeout()
    const controllers = [readOpts?.signal, timeout.signal].filter((s): s is AbortSignal => !!s)
    const signal = anySignal(controllers)
    try {
      // SECURITY: `redirect: 'error'` keeps requests on the validated base URL (SSRF).
      const res = await this._fetch(`${this._baseUrl}${path}`, { ...init, headers, signal, redirect: 'error' })
      if (res.status >= 500) {
        const body = await readBodyCapped(res)
        throw makeTransient(new Error(`[@gentleduck/iam:http] HTTP ${res.status}: ${body}`))
      }
      return res
    } finally {
      timeout.clear()
    }
  }

  /** Per-request timeout signal; `clear` must run once the request settles so the timer cannot outlive it. */
  private _timeout(): { signal?: AbortSignal; clear: () => void } {
    if (this._timeoutMs <= 0) return { clear: () => {} }
    const ctrl = new AbortController()
    const timer = setTimeout(
      () => ctrl.abort(makeTransient(new Error(`IamHttpAdapter request timed out after ${this._timeoutMs}ms`))),
      this._timeoutMs,
    )
    return { signal: ctrl.signal, clear: () => clearTimeout(timer) }
  }

  /** Lists every policy via `GET /policies`. */
  async listPolicies(opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const body = await this._request('/policies', undefined, opts)
    return this._narrowList(body, '/policies', (row, fallbackId) => this._narrowPolicy(row, fallbackId))
  }
  /** Fetches a policy by ID, or `null` on a 404 or an empty id. */
  async getPolicy(
    id: string,
    opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    if (typeof id !== 'string' || id.length === 0) return null
    const row = await this._requestOrNull(`/policies/${segment(id, 'policy id')}`, undefined, opts)
    return row === null ? null : this._narrowPolicy(row, id)
  }
  /** Stores or overwrites a policy via `PUT /policies`. */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    iamAssertSavablePolicy('http', p)
    assertReadableId(p?.id, 'policy id')
    await this._request('/policies', {
      method: 'PUT',
      body: JSON.stringify(iamNormalizePolicy(p)),
    })
  }
  /** Removes a policy by ID via DELETE. */
  async deletePolicy(id: string): Promise<void> {
    await this._request(`/policies/${segment(id, 'policy id')}`, { method: 'DELETE' })
  }

  /** Lists every role via `GET /roles`. */
  async listRoles(opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const body = await this._request('/roles', undefined, opts)
    return this._narrowList(body, '/roles', (row, fallbackId) => this._narrowRole(row, fallbackId))
  }
  /** Fetches a role by ID, or `null` on a 404 or an empty id. */
  async getRole(
    id: string,
    opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    if (typeof id !== 'string' || id.length === 0) return null
    const row = await this._requestOrNull(`/roles/${segment(id, 'role id')}`, undefined, opts)
    return row === null ? null : this._narrowRole(row, id)
  }
  /** Stores or overwrites a role via `PUT /roles`. */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    iamAssertSavableRole('http', r)
    assertReadableId(r?.id, 'role id')
    await this._request('/roles', { method: 'PUT', body: JSON.stringify(r) })
  }
  /**
   * Removes a role by ID via DELETE; `http-compliance.test.ts` has a reference server.
   * WARN: the server must also drop the role's grants, as `ON DELETE CASCADE` does; this adapter cannot sweep them.
   */
  async deleteRole(id: string): Promise<void> {
    await this._request(`/roles/${segment(id, 'role id')}`, { method: 'DELETE' })
  }

  /**
   * Lists a subject's unscoped role IDs via `GET /subjects/{id}/roles`; a malformed entry fails the whole read.
   * SECURITY: the server must omit scoped roles (see {@link IamHttpAdapter.getSubjectScopedRoles}); mixing them in grants too much.
   */
  async getSubjectRoles(subjectId: string, opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    if (typeof subjectId !== 'string' || subjectId.length === 0) return []
    const raw: unknown = await this._request(`/subjects/${segment(subjectId, 'subject id')}/roles`, undefined, opts)
    return parseHttpSubjectRoles<TRole>(raw, subjectId)
  }
  /** Lists a subject's scoped `(role, scope)` assignments via `GET /subjects/{id}/scoped-roles`; a malformed entry throws. */
  async getSubjectScopedRoles(
    subjectId: string,
    opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    if (typeof subjectId !== 'string' || subjectId.length === 0) return []
    const raw: unknown = await this._request(
      `/subjects/${segment(subjectId, 'subject id')}/scoped-roles`,
      undefined,
      opts,
    )
    return parseHttpSubjectScopedRoles<TRole, TScope>(raw, subjectId)
  }
  /**
   * Grants a role to a subject, optionally within a scope.
   * NOTE: the server decides whether the role exists; its non-2xx refusal surfaces as a throw.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('http', scope)
    iamAssertNoAssignOptions('http', opts)
    await this._request(`/subjects/${segment(subjectId, 'subject id')}/roles`, {
      method: 'POST',
      body: JSON.stringify({ roleId, scope }),
    })
  }
  /** Removes a role assignment from a subject; `scope`, when given, is sent as a query param. */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('http', scope, 'lookup')
    const params = scope !== undefined ? `?scope=${encodeURIComponent(scope)}` : ''
    await this._request(`/subjects/${segment(subjectId, 'subject id')}/roles/${segment(roleId, 'role id')}${params}`, {
      method: 'DELETE',
    })
  }
  /** Fetches a subject's attribute bag; a response that is not a flat object of scalars throws. */
  async getSubjectAttributes(subjectId: string, opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    if (typeof subjectId !== 'string' || subjectId.length === 0) return {}
    const raw: unknown = await this._request(
      `/subjects/${segment(subjectId, 'subject id')}/attributes`,
      undefined,
      opts,
    )
    return parseHttpSubjectAttributes(raw, subjectId)
  }
  /** Shallow-merges an attribute patch into the subject's bag via PATCH. */
  async setSubjectAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void> {
    iamAssertAttributesParam('http', subjectId, attrs)
    await this._request(`/subjects/${segment(subjectId, 'subject id')}/attributes`, {
      method: 'PATCH',
      body: JSON.stringify(attrs),
    })
  }
}

/** Reads up to 200 chars of the response body, for error messages. */
async function readBodyCapped(res: Response): Promise<string> {
  // SECURITY: stream with a 4 KB cap; `res.text()` would buffer a hostile multi-GB body first.
  const MAX_BYTES = 4096
  const reader = res.body?.getReader()
  if (!reader) {
    try {
      const t = await res.text()
      return t.length <= 200 ? t : `${t.slice(0, 200)}...(truncated)`
    } catch {
      return ''
    }
  }
  const decoder = new TextDecoder()
  let acc = ''
  let bytes = 0
  try {
    while (bytes < MAX_BYTES) {
      const { value, done } = await reader.read()
      if (done) break
      bytes += value.byteLength
      acc += decoder.decode(value, { stream: true })
      if (bytes >= MAX_BYTES) break
    }
    acc += decoder.decode()
  } catch {
    /* swallow stream errors; partial body is fine for diagnostics */
  } finally {
    void reader.cancel().catch(() => {})
  }
  if (acc.length <= 200) return acc
  return `${acc.slice(0, 200)}...(truncated)`
}

/**
 * Reads a JSON body as `unknown` for callers to validate; an empty body is `undefined`, not a parse error.
 * SECURITY: refuses bodies past 4 MiB while streaming, so a hostile remote cannot OOM us before `JSON.parse`.
 */
async function readJsonCapped(res: Response): Promise<unknown> {
  const MAX_BYTES = 4 * 1024 * 1024
  // `204 No Content` and `205 Reset Content` are bodiless by definition.
  if (res.status === 204 || res.status === 205) return undefined
  const reader = res.body?.getReader()
  if (!reader) {
    const raw = await res.text()
    return raw === '' ? undefined : JSON.parse(raw)
  }
  const decoder = new TextDecoder()
  let text = ''
  let bytes = 0
  try {
    while (bytes < MAX_BYTES) {
      const { value, done } = await reader.read()
      if (done) break
      bytes += value.byteLength
      text += decoder.decode(value, { stream: true })
      if (bytes >= MAX_BYTES) {
        throw new Error('[@gentleduck/iam:http] response body exceeds 4 MiB cap')
      }
    }
    text += decoder.decode()
  } finally {
    void reader.cancel().catch(() => {})
  }
  return text === '' ? undefined : JSON.parse(text)
}

function parseHttpSubjectAttributes(value: unknown, subjectId: string): IamPrimitives.Attributes {
  const attrs = iamNarrowAttributes(value)
  if (attrs === null) {
    const got = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value
    throw new Error(
      `[@gentleduck/iam:http] getSubjectAttributes for "${subjectId}" returned ${got} (expected a JSON object of scalar values)`,
    )
  }
  return attrs
}

/** Names the malformed element's type without echoing it, so a bad payload cannot be reflected into the error. */
function describeEntry(entry: unknown): string {
  if (entry === null) return 'null'
  if (Array.isArray(entry)) return 'array'
  if (typeof entry === 'string') return entry.length === 0 ? 'empty string' : 'string'
  return typeof entry
}

function parseHttpSubjectRoles<TRole extends string>(value: unknown, subjectId: string): TRole[] {
  if (!Array.isArray(value)) {
    const got = value === null ? 'null' : typeof value
    throw new Error(`[@gentleduck/iam:http] getSubjectRoles for "${subjectId}" returned ${got} (expected JSON array)`)
  }
  const roles: TRole[] = []
  for (let i = 0; i < value.length; i++) {
    const entry = value[i]
    // SECURITY: a dropped grant retires every policy whose `targets.roles` names it, turning a deny into an allow.
    if (typeof entry !== 'string' || entry.length === 0) {
      throw new Error(
        `[@gentleduck/iam:http] getSubjectRoles for "${subjectId}" returned ${describeEntry(entry)} at [${i}] ` +
          '(expected a non-empty string). A partial role list is not a smaller one: a role also carries the ' +
          'denies that target it, so the missing entry reads as permission rather than as a failed read.',
      )
    }
    roles.push(iamAsRoleLiteral(entry))
  }
  return roles
}

function parseHttpSubjectScopedRoles<TRole extends string, TScope extends string>(
  value: unknown,
  subjectId: string,
): IamRequest.IScopedRole<TRole, TScope>[] {
  if (!Array.isArray(value)) {
    const got = value === null ? 'null' : typeof value
    throw new Error(
      `[@gentleduck/iam:http] getSubjectScopedRoles for "${subjectId}" returned ${got} (expected JSON array)`,
    )
  }
  const out: IamRequest.IScopedRole<TRole, TScope>[] = []
  for (let i = 0; i < value.length; i++) {
    const entry = value[i]
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error(
        `[@gentleduck/iam:http] getSubjectScopedRoles for "${subjectId}" returned ${describeEntry(entry)} at [${i}] ` +
          '(expected a {role, scope} object)',
      )
    }
    const role = Reflect.get(entry, 'role')
    const scope = Reflect.get(entry, 'scope')
    // The endpoints are disjoint by contract, so an unscoped row here is the server mixing them, not a global grant.
    if (typeof role !== 'string' || role.length === 0 || typeof scope !== 'string' || scope.length === 0) {
      throw new Error(
        `[@gentleduck/iam:http] getSubjectScopedRoles for "${subjectId}" returned an entry at [${i}] whose ` +
          `role is ${describeEntry(role)} and scope is ${describeEntry(scope)} (both must be non-empty strings). ` +
          'A dropped scoped grant silently retires the denies that target that role.',
      )
    }
    out.push({ role: iamAsRoleLiteral(role), scope: iamAsScopeLiteral(scope) })
  }
  return out
}

/** Factory around {@link IamHttpAdapter}, for callers who prefer functions to `new`. */
export function iamHttpAdapter(...args: ConstructorParameters<typeof IamHttpAdapter>): IamHttpAdapter {
  return new IamHttpAdapter(...args)
}
