import { fail, throwIamError } from '../../core/errors'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import { iamRowErrorReporter } from '../../shared/row-error-reporter'
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
     * Permits a `baseUrl` that is an IP literal outside the public internet: private, loopback, link-local, CGNAT,
     * multicast, reserved or documentation, or an IPv6 form carrying an IPv4. Defaults to `false`.
     * INFO: DNS names are not resolved (that would need sync I/O), so only `allowedHosts` constrains them.
     */
    allowPrivateHosts?: boolean
  }
}

/** One-time latch for the omitted-`allowedHosts` warning; module-level so repeated constructions do not spam. */
const _ALLOWED_HOSTS_WARNED = { fired: false }

/** RFC 1918, RFC 6598, RFC 5735 and the ranges that are not routable on the public internet. */
const V4_BLOCKED: Array<{ mask: number; net: number }> = [
  { mask: 0xff000000, net: 0x00000000 }, // 0.0.0.0/8 this network
  { mask: 0xff000000, net: 0x0a000000 }, // 10.0.0.0/8
  { mask: 0xffc00000, net: 0x64400000 }, // 100.64.0.0/10 cgnat
  { mask: 0xff000000, net: 0x7f000000 }, // 127.0.0.0/8 loopback
  { mask: 0xffff0000, net: 0xa9fe0000 }, // 169.254.0.0/16 link-local, incl. 169.254.169.254
  { mask: 0xfff00000, net: 0xac100000 }, // 172.16.0.0/12
  { mask: 0xffffff00, net: 0xc0000000 }, // 192.0.0.0/24 ietf protocol assignments
  { mask: 0xffffff00, net: 0xc0000200 }, // 192.0.2.0/24 documentation, RFC 5737 TEST-NET-1
  { mask: 0xffff0000, net: 0xc0a80000 }, // 192.168.0.0/16
  { mask: 0xfffe0000, net: 0xc6120000 }, // 198.18.0.0/15 benchmarking
  { mask: 0xffffff00, net: 0xc6336400 }, // 198.51.100.0/24 documentation, RFC 5737 TEST-NET-2
  { mask: 0xffffff00, net: 0xcb007100 }, // 203.0.113.0/24 documentation, RFC 5737 TEST-NET-3
  { mask: 0xf0000000, net: 0xe0000000 }, // 224.0.0.0/4 multicast
  { mask: 0xf0000000, net: 0xf0000000 }, // 240.0.0.0/4 reserved, incl. 255.255.255.255
]

/** Parses a dotted-quad into a 32-bit number, or `null` when the string is not one. */
function _parseIpv4(host: string): number | null {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (part.length === 0 || part.length > 3 || !/^[0-9]+$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = value * 256 + octet
  }
  return value >>> 0
}

/** Parses an IPv6 literal, with or without brackets, into its eight hextets, or `null` when it is not one. */
function _parseIpv6(host: string): number[] | null {
  let text = host
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1)
  const zone = text.indexOf('%')
  if (zone !== -1) text = text.slice(0, zone)
  if (!text.includes(':')) return null

  const [head, tail, ...rest] = text.split('::')
  if (rest.length > 0 || head === undefined) return null

  const expand = (group: string): number[] | null => {
    if (group === '') return []
    const out: number[] = []
    const pieces = group.split(':')
    for (const [i, piece] of pieces.entries()) {
      // A trailing dotted-quad occupies the last two hextets (`::ffff:1.2.3.4`).
      if (i === pieces.length - 1 && piece.includes('.')) {
        const v4 = _parseIpv4(piece)
        if (v4 === null) return null
        out.push(v4 >>> 16, v4 & 0xffff)
        continue
      }
      if (!/^[0-9a-f]{1,4}$/i.test(piece)) return null
      out.push(Number.parseInt(piece, 16))
    }
    return out
  }

  const left = expand(head)
  const right = tail === undefined ? [] : expand(tail)
  if (left === null || right === null) return null
  if (tail === undefined) return left.length === 8 ? left : null
  const gap = 8 - left.length - right.length
  if (gap < 1) return null
  return [...left, ...Array.from({ length: gap }, () => 0), ...right]
}

/** Whether parsed hextets fall outside the public internet. */
function _isBlockedIpv6(h: number[]): boolean {
  const [h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0] = h
  if (h.every((x) => x === 0)) return true // ::
  if (h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0 && h5 === 0) return true // ::1 and ::a.b.c.d
  if (h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0 && h5 === 0xffff) return true // ::ffff:0:0/96
  if (h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0xffff && h5 === 0) return true // ::ffff:0:0:0/96 siit
  if ((h0 & 0xfe00) === 0xfc00) return true // fc00::/7 unique-local
  if ((h0 & 0xffc0) === 0xfe80) return true // fe80::/10 link-local
  if ((h0 & 0xffc0) === 0xfec0) return true // fec0::/10 site-local, deprecated but still routed where configured
  if ((h0 & 0xff00) === 0xff00) return true // ff00::/8 multicast
  if (h0 === 0x0100 && h1 === 0 && h2 === 0 && h3 === 0) return true // 100::/64 discard-only
  if (h0 === 0x0064 && h1 === 0xff9b) return true // 64:ff9b::/32 nat64
  if (h0 === 0x2002) return true // 2002::/16 6to4
  if (h0 === 0x2001 && h1 === 0x0000) return true // 2001::/32 teredo
  if (h0 === 0x2001 && h1 === 0x0002 && h2 === 0) return true // 2001:2::/48 benchmarking, RFC 5180
  if (h0 === 0x2001 && h1 === 0x0db8) return true // 2001:db8::/32 documentation, RFC 3849
  if (h0 === 0x3fff && (h1 & 0xf000) === 0) return true // 3fff::/20 documentation, RFC 9637
  if (h0 === 0x5f00) return true // 5f00::/16 srv6 segment ids, RFC 9602
  return false
}

/**
 * True for an IP literal outside the public internet; DNS names return `false`.
 * SECURITY: an IPv6 form that carries an IPv4 (mapped, compatible, SIIT, 6to4, NAT64, Teredo) is refused whole, so
 * no unwrapping can miss a private address inside one.
 */
function _isPrivateHost(hostname: string): boolean {
  const host = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname
  const v4 = _parseIpv4(host)
  if (v4 !== null) return V4_BLOCKED.some((range) => (v4 & range.mask) >>> 0 === range.net)
  const v6 = _parseIpv6(host)
  return v6 !== null && _isBlockedIpv6(v6)
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
    throwIamError('IAM_HTTP_ID_INVALID', { field, reason: 'empty' })
  }
  if (value.includes('/') || value.includes('\\')) {
    throwIamError('IAM_HTTP_ID_INVALID', { field, reason: 'separator' })
  }
  if (/^\.+$/.test(value)) {
    throwIamError('IAM_HTTP_ID_INVALID', { field, reason: 'dot-segment', value })
  }
  if (value.length > MAX_ID_LENGTH) {
    throwIamError('IAM_HTTP_ID_INVALID', { field, reason: 'too-long', length: value.length })
  }
  return encodeURIComponent(value)
}

/** Rejects an id the read path could never fetch back; `savePolicy`/`saveRole` send it in the body, not the path. */
function assertReadableId(id: unknown, field: string): void {
  if (typeof id !== 'string') {
    throwIamError('IAM_HTTP_ID_INVALID', { field, reason: 'empty' })
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
  private _reportPolicyError: (err: Error, rowId: string) => void
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
    this._reportPolicyError = iamRowErrorReporter('http', config.onPolicyError)
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
      throwIamError('IAM_HTTP_OPTION_INVALID', {
        field: name,
        got: JSON.stringify(value),
        constraint: `finite ${bounds.integer === true ? 'integer' : 'number'} >= ${bounds.min}`,
      })
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
      throwIamError('IAM_HTTP_BASE_URL_INVALID', { reason: 'unparseable', baseUrl: config.baseUrl })
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throwIamError('IAM_HTTP_BASE_URL_INVALID', { reason: 'bad-scheme', scheme: parsed.protocol })
    }
    // Tested on the raw string too: `new URL('https://h/iam?').search` is `''`, so a trailing bare `?` -
    // what a URL builder emits for empty search params - would otherwise pass this guard.
    if (parsed.search || parsed.hash || config.baseUrl.includes('?') || config.baseUrl.includes('#')) {
      throwIamError('IAM_HTTP_BASE_URL_INVALID', { reason: 'has-query-or-fragment' })
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
        throwIamError('IAM_HTTP_BASE_URL_INVALID', { reason: 'host-not-allowed', host: parsed.host })
      }
    } else if (!_ALLOWED_HOSTS_WARNED.fired) {
      _ALLOWED_HOSTS_WARNED.fired = true
      console.warn(
        '[@gentleduck/iam:http] `allowedHosts` not set - any host accepted. Pass `init.allowedHosts` for SSRF defense in depth.',
      )
    }
    if (!config.allowPrivateHosts && _isPrivateHost(parsed.hostname)) {
      throwIamError('IAM_HTTP_BASE_URL_INVALID', { reason: 'private-host', host: parsed.hostname })
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
      throwIamError('IAM_HTTP_RESPONSE_ERROR', { status: res.status, body: await readBodyCapped(res) })
    }
    return readJsonCapped(res)
  }

  /**
   * Narrows one API row to a policy.
   * SECURITY: a mismatch is reported and throws, never dropped or returned raw; see {@link iamUnreadablePolicy}.
   */
  private _narrowPolicy(row: unknown, fallbackId: string): AccessControl.IPolicy<TAction, TResource, TRole> {
    const policy = parsePolicyRow<TAction, TResource, TRole>(row)
    if (policy !== null) return policy
    const rowId = rowIdOf(row, fallbackId)
    const issues = validatePolicy(row)
      .issues.map((i) => i.message)
      .join('; ')
    this._reportPolicyError(new Error(`Invalid policy "${rowId}": ${issues}`), rowId)
    throw iamUnreadablePolicy('http', rowId, issues)
  }

  private _narrowRole(row: unknown, fallbackId: string): AccessControl.IRole<TAction, TResource, TRole, TScope> {
    const role = parseRoleRow<TAction, TResource, TRole, TScope>(row)
    if (role !== null) return role
    const rowId = rowIdOf(row, fallbackId)
    const issues = validateRole(row)
      .issues.map((i) => i.message)
      .join('; ')
    this._reportPolicyError(new Error(`Invalid role "${rowId}": ${issues}`), rowId)
    throw iamUnreadableRole('http', rowId, issues)
  }

  /** A list endpoint must return an array; anything else is reported and rejected, never read as an empty list. */
  private _narrowList<T>(body: unknown, path: string, narrow: (row: unknown, fallbackId: string) => T): T[] {
    if (!Array.isArray(body)) {
      const got = body === null ? 'null' : typeof body
      const err = fail('IAM_HTTP_LIST_INVALID', { path, got })
      this._reportPolicyError(err, path)
      throw err
    }
    const out: T[] = []
    for (const [i, row] of body.entries()) out.push(narrow(row, `${path}[${i}]`))
    return out
  }

  /** Like {@link IamHttpAdapter._request}, but a 404 returns `null`, per the "row or null" contract of `getPolicy`/`getRole`. */
  private async _requestOrNull(path: string, init?: IHttpInit, readOpts?: IamAdapter.IReadOptions): Promise<unknown> {
    const res = await this._fetchWithRetry(path, init, readOpts)
    if (res.status === 404) return null
    if (!res.ok) {
      throwIamError('IAM_HTTP_RESPONSE_ERROR', { status: res.status, body: await readBodyCapped(res) })
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
      throwIamError('IAM_HTTP_CIRCUIT_OPEN', { state: 'open' })
    }
    if (state === 'half-open') {
      if (this._cbHalfOpenInFlight) {
        throwIamError('IAM_HTTP_CIRCUIT_OPEN', { state: 'half-open-busy' })
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
    throwIamError('IAM_HTTP_RETRY_EXHAUSTED', { path })
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
        throw makeTransient(fail('IAM_HTTP_RESPONSE_ERROR', { status: res.status, body }))
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
    // The id travels in the body here and in the path on revoke, so only `segment` used to see it: an id
    // holding `/` assigned cleanly and then failed every `revokeRole`. Reads and writes share the invariant.
    assertReadableId(roleId, 'role id')
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
        throwIamError('IAM_HTTP_RESPONSE_TOO_LARGE', { capBytes: MAX_BYTES })
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
    throwIamError('IAM_ATTRIBUTES_CORRUPT', { adapter: 'http', subjectId, reason: 'not-object' })
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
    throwIamError('IAM_HTTP_SUBJECT_ROLES_INVALID', { subjectId, reason: 'not-array', got })
  }
  const roles: TRole[] = []
  for (let i = 0; i < value.length; i++) {
    const entry: unknown = value[i]
    // SECURITY: a dropped grant retires every policy whose `targets.roles` names it, turning a deny into an allow.
    if (typeof entry !== 'string' || entry.length === 0) {
      throwIamError('IAM_HTTP_SUBJECT_ROLES_INVALID', {
        subjectId,
        reason: 'entry-invalid',
        index: i,
        got: describeEntry(entry),
      })
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
    throwIamError('IAM_HTTP_SUBJECT_SCOPED_ROLES_INVALID', { subjectId, reason: 'not-array', got })
  }
  const out: IamRequest.IScopedRole<TRole, TScope>[] = []
  for (let i = 0; i < value.length; i++) {
    const entry: unknown = value[i]
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throwIamError('IAM_HTTP_SUBJECT_SCOPED_ROLES_INVALID', {
        subjectId,
        reason: 'entry-not-object',
        index: i,
        got: describeEntry(entry),
      })
    }
    const role = Reflect.get(entry, 'role')
    const scope = Reflect.get(entry, 'scope')
    // The endpoints are disjoint by contract, so an unscoped row here is the server mixing them, not a global grant.
    if (typeof role !== 'string' || role.length === 0 || typeof scope !== 'string' || scope.length === 0) {
      throwIamError('IAM_HTTP_SUBJECT_SCOPED_ROLES_INVALID', {
        subjectId,
        reason: 'entry-fields-invalid',
        index: i,
        role: describeEntry(role),
        scope: describeEntry(scope),
      })
    }
    out.push({ role: iamAsRoleLiteral(role), scope: iamAsScopeLiteral(scope) })
  }
  return out
}

/** Factory around {@link IamHttpAdapter}, for callers who prefer functions to `new`. */
export function iamHttpAdapter(...args: ConstructorParameters<typeof IamHttpAdapter>): IamHttpAdapter {
  return new IamHttpAdapter(...args)
}
