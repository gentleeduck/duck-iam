import type { AccessControl, Adapter, Primitives, Request } from '../../core/types'

/** Brand symbol marking an error as retry-eligible. Internal to this adapter. */
const TRANSIENT = Symbol('duck-iam.http.transient')

/** Tags an Error as transient so `isTransientError` will pick it up. Returns the same instance. */
function makeTransient<T extends Error>(err: T): T {
  Reflect.set(err, TRANSIENT, true)
  return err
}

/**
 * Returns `true` if the error should trigger a retry: anything tagged with
 * {@link TRANSIENT}, fetch `AbortError`/`TypeError`, or common Node socket
 * codes (`ECONNRESET`, `ECONNREFUSED`, `ETIMEDOUT`, `ENOTFOUND`).
 */
function isTransientError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false
  if (Reflect.get(err, TRANSIENT) === true) return true
  const name = Reflect.get(err, 'name')
  if (name === 'AbortError' || name === 'TypeError') return true
  const code = Reflect.get(err, 'code')
  return code === 'ECONNRESET' || code === 'ECONNREFUSED' || code === 'ETIMEDOUT' || code === 'ENOTFOUND'
}

/**
 * Composes multiple AbortSignals into one that aborts when any source aborts.
 *
 * Used to layer the per-request fetch timeout with the engine's
 * `adapterTimeoutMs` and any user-supplied `IReadOptions.signal`.
 */
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
/**
 * HTTP adapter integration types. Type-only namespace - zero bundle cost.
 */
export namespace Http {
  /**
   * Describes the configuration for {@link HttpAdapter}.
   *
   * Covers endpoint, fetch overrides, retry, and circuit-breaker tuning.
   */
  export interface IConfig {
    /** Specifies the base URL of the duck-iam API (e.g. `https://api.example.com/access`). */
    baseUrl: string
    /** Overrides the default `globalThis.fetch` implementation. */
    fetch?: typeof globalThis.fetch
    /** Provides headers (e.g. auth tokens) merged into every request. */
    headers?: Record<string, string> | (() => Record<string, string> | Promise<Record<string, string>>)
    /**
     * Sets the per-request timeout in milliseconds.
     *
     * Layered with the engine's `adapterTimeoutMs`; whichever fires first wins.
     * Defaults to `5_000`. Set to `0` to rely solely on the engine timeout.
     */
    timeoutMs?: number
    /**
     * Caps retry attempts on transient failures (5xx, network errors, or
     * `AbortError` from a per-request timeout).
     *
     * 4xx responses are never retried. Defaults to `2` (3 total attempts).
     */
    retries?: number
    /**
     * Sets the base delay in ms for exponential backoff between retries.
     *
     * Attempt N waits `backoffMs * 2^(N-1)` plus jitter. Defaults to `100`.
     */
    backoffMs?: number
    /**
     * Opens the circuit after this many consecutive transient failures.
     *
     * Once open, requests reject immediately until the cooldown elapses. Default
     * `5`. Set to `0` to disable.
     */
    circuitBreakerThreshold?: number
    /**
     * Sets the half-open cooldown in ms.
     *
     * After this window, the next request is allowed through as a probe; success
     * closes the circuit, failure re-opens it. Default `30_000` (30 s).
     */
    circuitBreakerCooldownMs?: number
    /**
     * Restricts the set of acceptable hosts for `baseUrl`. When set, the
     * parsed URL must match an entry in the list or construction throws.
     *
     * Matching rules:
     * - Comparison is case-insensitive on both sides - `Example.COM` in the
     *   list matches `example.com` in `baseUrl` and vice versa.
     * - Entries may be bare hostnames (`example.com`) or host:port pairs
     *   (`example.com:8080`).
     * - A bare-host entry matches the URL's hostname regardless of port - so
     *   `allowedHosts: ['example.com']` accepts `example.com`, `example.com:80`,
     *   and `example.com:8443`.
     * - A host:port entry matches only that exact port - `example.com:8080`
     *   rejects `example.com` (no port) and `example.com:9090`.
     * - Precedence: bare hostname is tried first, then full `host` (with port).
     *
     * Defaults to `undefined` (allow any host); when omitted a one-time
     * `console.warn` is emitted at construction recommending a list.
     */
    allowedHosts?: string[]
    /**
     * Permits `baseUrl` whose hostname is an IP literal in a private/loopback
     * range (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
     * `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`). Defaults to `false`.
     * DNS names are not resolved (would require sync I/O at init); they pass
     * through and are only constrained by `allowedHosts`.
     */
    allowPrivateHosts?: boolean
  }
}

/**
 * One-time warning latch for omitted `allowedHosts`. Module-level so repeated
 * adapter constructions during tests / per-request scopes don't spam stderr.
 */
const _ALLOWED_HOSTS_WARNED = { fired: false }

/**
 * Converts a 32-bit IPv4 tail expressed as two colon-separated hex groups
 * (e.g. `7f00:1`) into dotted-quad form (`127.0.0.1`). Returns `null` if the
 * input is not a well-formed 32-bit hex tail. Both groups may be 1-4 hex
 * digits; the second group may be omitted leading zeros (`7f00:1` ==
 * `7f00:0001`).
 */
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
 * Returns `true` when the given hostname is an IP literal in a private,
 * loopback, link-local, or unique-local range. DNS names return `false`
 * (caller controls them via `allowedHosts`).
 */
function _isPrivateHost(hostname: string): boolean {
  // Strip surrounding brackets from IPv6 literals and a single trailing FQDN
  // dot so `127.0.0.1.` / `example.com.` normalise to their bare form before
  // the rest of the checks fire.
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
    // IPv6 unspecified `::` (kernel wildcard, often resolves to a local
    // interface). Block its expanded form too.
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true
    // fc00::/7 - first byte 0xfc or 0xfd
    if (/^f[cd][0-9a-f]{0,2}:/.test(lower)) return true
    // fe80::/10 - fe8x, fe9x, feax, febx
    if (/^fe[89ab][0-9a-f]?:/.test(lower)) return true
    // IPv4-mapped IPv6 - `::ffff:a.b.c.d` (dotted-quad tail) or
    // `::ffff:hhhh:hhhh` (hex tail, canonical form Node's URL parser emits).
    // Also accept the fully expanded `0:0:0:0:0:ffff:...` form.
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
    // IPv4-compatible IPv6 (deprecated RFC4291 §2.5.5.1) - `::a.b.c.d`.
    // Node canonicalises these to hex too, but cover textual form for
    // completeness.
    if (lower.startsWith('::') && lower.includes('.')) {
      const tail = lower.slice(2)
      if (/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(tail)) return _isPrivateHost(tail)
    }
    // 6to4 prefix `2002::/16` carries an inner IPv4 in the next two 16-bit
    // groups (`2002:AABB:CCDD::` -> `A.B.C.D` with bytes AA,BB,CC,DD). Linux
    // ships 6to4 by default - `2002:7f00:1::` carries `127.0.0.1`.
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

/**
 * Normalise a hostname for allowlist comparison.
 *
 * - Lower-cases.
 * - Strips a single trailing FQDN dot (`example.com.` -> `example.com`).
 * - Converts a Unicode hostname (anything outside ASCII) to its WHATWG-URL
 *   punycode form by round-tripping through `new URL`. Node's `URL` parser
 *   already returns the `xn--` form for `parsed.hostname`, so this only
 *   matters when an `allowedHosts` entry was authored in Unicode (e.g.
 *   `münchen.de`) while the URL host is `xn--mnchen-3ya.de`.
 *
 * Invalid input falls back to the lowercased + dot-stripped string so a
 * malformed allowlist entry never silently widens the match.
 */
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

/**
 * Backs the access store with a remote [@gentleduck/iam:http] HTTP API.
 *
 * Useful for client-side engines that delegate storage to a backend service.
 * Adds per-request timeout, exponential-backoff retry, and a circuit breaker.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @example
 * ```ts
 * const adapter = new HttpAdapter({
 *   baseUrl: 'https://api.example.com/access',
 *   headers: { Authorization: 'Bearer ...' },
 * })
 * ```
 */
export class HttpAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements Adapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private _baseUrl: string
  private _fetch: typeof globalThis.fetch
  private _headers: Http.IConfig['headers']
  private _timeoutMs: number
  private _retries: number
  private _backoffMs: number
  private _cbThreshold: number
  private _cbCooldownMs: number
  // Circuit-breaker state. closed -> too many transients -> open -> cooldown
  // expires -> half-open -> success closes / failure re-opens.
  private _cbConsecutiveFailures = 0
  private _cbOpenedAt: number | null = null
  private _cbHalfOpenInFlight = false

  /**
   * Creates a new HTTP adapter.
   *
   * @param config - Provides endpoint, fetch overrides, retry, and breaker tuning.
   */
  constructor(config: Http.IConfig) {
    this._baseUrl = HttpAdapter._validateBaseUrl(config)
    this._fetch = config.fetch ?? globalThis.fetch.bind(globalThis)
    this._headers = config.headers
    this._timeoutMs = config.timeoutMs ?? 5_000
    this._retries = config.retries ?? 2
    this._backoffMs = config.backoffMs ?? 100
    this._cbThreshold = config.circuitBreakerThreshold ?? 5
    this._cbCooldownMs = config.circuitBreakerCooldownMs ?? 30_000
  }

  /**
   * Validates `baseUrl` at construction time. Rejects non-`http(s)` schemes,
   * trailing query/fragment, hosts not in the allow-list, and private/loopback
   * IP literals when `allowPrivateHosts` is `false`. Emits a one-time warn
   * recommending `allowedHosts` when omitted. Returns the canonical base URL
   * with any trailing `/` stripped (for back-compat with the previous behaviour).
   */
  private static _validateBaseUrl(config: Http.IConfig): string {
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
    // Strip a single trailing `/` for back-compat with previous behaviour.
    return config.baseUrl.replace(/\/$/, '')
  }

  /**
   * Gates fetch attempts based on circuit state.
   *
   * - closed: pass through.
   * - open: reject immediately until the cooldown elapses.
   * - half-open: allow exactly one probe; concurrent callers reject while the
   *   probe is in flight. The probe's outcome closes or re-opens the circuit.
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

  /** Sends an HTTP request to the API, merging headers and parsing the JSON response. */
  private async _request<T>(path: string, init?: RequestInit, readOpts?: Adapter.IReadOptions): Promise<T> {
    const res = await this._fetchWithRetry(path, init, readOpts)
    if (!res.ok) {
      throw new Error(`[@gentleduck/iam:http] HTTP ${res.status}: ${await readBodyCapped(res)}`)
    }
    return readJsonCapped<T>(res)
  }

  /**
   * Same as {@link _request} but treats `404 Not Found` as a missing-resource
   * signal and returns `null` instead of throwing. The `Adapter.IAdapter`
   * contract for `getPolicy`/`getRole` is "the role, or null if not found";
   * the previous throw-on-every-non-2xx behaviour broke that contract and
   * caused engine.resolve() to bubble up a hard error on every cold miss.
   */
  private async _requestOrNull<T>(
    path: string,
    init?: RequestInit,
    readOpts?: Adapter.IReadOptions,
  ): Promise<T | null> {
    const res = await this._fetchWithRetry(path, init, readOpts)
    if (res.status === 404) return null
    if (!res.ok) {
      throw new Error(`[@gentleduck/iam:http] HTTP ${res.status}: ${await readBodyCapped(res)}`)
    }
    return readJsonCapped<T>(res)
  }

  /**
   * Fetches with per-request timeout and exponential-backoff retry on transient
   * failures.
   *
   * Transient covers 5xx, network errors, or our own timeout abort. 4xx is
   * treated as a definitive answer and returned without retry.
   */
  private async _fetchWithRetry(
    path: string,
    init: RequestInit | undefined,
    readOpts?: Adapter.IReadOptions,
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
        // Cap exponential backoff so misconfigured `_retries` cannot drive the
        // delay past 2^31 ms (setTimeout overflow).
        const exp = Math.min(this._backoffMs * 2 ** attempt, 60_000)
        const delay = exp + Math.floor(Math.random() * Math.min(this._backoffMs, 5000))
        await new Promise((r) => setTimeout(r, delay))
        attempt++
      }
    }
    this._onCircuitFailure()
    throw lastError as Error
  }

  private async _fetchOnce(
    path: string,
    init: RequestInit | undefined,
    readOpts?: Adapter.IReadOptions,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(typeof this._headers === 'function' ? await this._headers() : (this._headers ?? {})),
      ...((init?.headers as Record<string, string>) ?? {}),
    }
    const controllers = [readOpts?.signal, this._timeoutSignal()].filter((s): s is AbortSignal => !!s)
    const signal = anySignal(controllers)
    // SSRF defence: `redirect: 'error'` keeps the validated base URL.
    const res = await this._fetch(`${this._baseUrl}${path}`, { ...init, headers, signal, redirect: 'error' })
    if (res.status >= 500) {
      const body = await readBodyCapped(res)
      throw makeTransient(new Error(`[@gentleduck/iam:http] HTTP ${res.status}: ${body}`))
    }
    return res
  }

  private _timeoutSignal(): AbortSignal | undefined {
    if (this._timeoutMs <= 0) return undefined
    const ctrl = new AbortController()
    setTimeout(
      () => ctrl.abort(makeTransient(new Error(`HttpAdapter request timed out after ${this._timeoutMs}ms`))),
      this._timeoutMs,
    )
    return ctrl.signal
  }

  /**
   * Lists every policy from the remote API.
   *
   * @param opts - Optional read options forwarded to fetch.
   * @returns Array of policies returned by `GET /policies`.
   */
  async listPolicies(opts?: Adapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    return this._request('/policies', undefined, opts)
  }
  /**
   * Fetches a single policy by ID.
   *
   * @param id - Identifies the policy to look up.
   * @param opts - Optional read options forwarded to fetch.
   * @returns The matching policy or `null` when the API returns 404.
   */
  async getPolicy(
    id: string,
    opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    if (typeof id !== 'string' || id.length === 0 || id.length > 1024) return null
    return this._requestOrNull(`/policies/${encodeURIComponent(id)}`, undefined, opts)
  }
  /**
   * Stores or overwrites a policy via PUT.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the API acknowledges the write.
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    await this._request('/policies', {
      method: 'PUT',
      body: JSON.stringify(p),
    })
  }
  /**
   * Removes a policy by ID via DELETE.
   *
   * @param id - Identifies the policy to delete.
   * @returns Resolves once the API acknowledges the delete.
   */
  async deletePolicy(id: string): Promise<void> {
    await this._request(`/policies/${encodeURIComponent(id)}`, { method: 'DELETE' })
  }

  /**
   * Lists every role from the remote API.
   *
   * @param opts - Optional read options forwarded to fetch.
   * @returns Array of roles returned by `GET /roles`.
   */
  async listRoles(opts?: Adapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    return this._request('/roles', undefined, opts)
  }
  /**
   * Fetches a single role by ID.
   *
   * @param id - Identifies the role to look up.
   * @param opts - Optional read options forwarded to fetch.
   * @returns The matching role or `null` when the API returns 404.
   */
  async getRole(
    id: string,
    opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    if (typeof id !== 'string' || id.length === 0 || id.length > 1024) return null
    return this._requestOrNull(`/roles/${encodeURIComponent(id)}`, undefined, opts)
  }
  /**
   * Stores or overwrites a role via PUT.
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the API acknowledges the write.
   */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    await this._request('/roles', { method: 'PUT', body: JSON.stringify(r) })
  }
  /**
   * Removes a role by ID via DELETE.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the API acknowledges the delete.
   */
  async deleteRole(id: string): Promise<void> {
    await this._request(`/roles/${encodeURIComponent(id)}`, { method: 'DELETE' })
  }

  /**
   * Lists role IDs assigned to a subject.
   *
   * **Contract:** the response MUST contain GLOBAL (unscoped) role IDs
   * only. Scoped role assignments must be returned
   * from `GET /subjects/{id}/scoped-roles` (see {@link getSubjectScopedRoles}).
   * The HTTP adapter cannot enforce this - it forwards whatever the server
   * returns - so the operator's API server is responsible for filtering
   * out scoped roles. A server that collapses scoped+unscoped into one list
   * will cause subjects to evaluate with MORE permissions than they would
   * against any other adapter (memory, file, redis, drizzle, prisma),
   * silently breaking authorization parity across backends.
   *
   * @param subjectId - Identifies the subject whose roles are read.
   * @param opts - Optional read options forwarded to fetch.
   * @returns Array of UNSCOPED role IDs returned by `GET /subjects/{id}/roles`.
   */
  async getSubjectRoles(subjectId: string, opts?: Adapter.IReadOptions): Promise<TRole[]> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return []
    const raw: unknown = await this._request(`/subjects/${encodeURIComponent(subjectId)}/roles`, undefined, opts)
    return parseHttpSubjectRoles<TRole>(raw, subjectId)
  }
  /**
   * Lists scoped role assignments for a subject.
   *
   * @param subjectId - Identifies the subject whose scoped roles are read.
   * @param opts - Optional read options forwarded to fetch.
   * @returns Array of `(role, scope)` pairs.
   */
  async getSubjectScopedRoles(
    subjectId: string,
    opts?: Adapter.IReadOptions,
  ): Promise<Request.IScopedRole<TRole, TScope>[]> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return []
    const raw: unknown = await this._request(`/subjects/${encodeURIComponent(subjectId)}/scoped-roles`, undefined, opts)
    return parseHttpSubjectScopedRoles<TRole, TScope>(raw, subjectId)
  }
  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * @param subjectId - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the API acknowledges the write.
   */
  async assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    await this._request(`/subjects/${encodeURIComponent(subjectId)}/roles`, {
      method: 'POST',
      body: JSON.stringify({ roleId, scope }),
    })
  }
  /**
   * Removes a role assignment from a subject.
   *
   * @param subjectId - Identifies the subject losing the role.
   * @param roleId - Specifies the role being revoked.
   * @param scope - Optional scope filter passed as a query param.
   * @returns Resolves once the API acknowledges the delete.
   */
  async revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void> {
    const params = scope ? `?scope=${encodeURIComponent(scope)}` : ''
    await this._request(`/subjects/${encodeURIComponent(subjectId)}/roles/${encodeURIComponent(roleId)}${params}`, {
      method: 'DELETE',
    })
  }
  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param subjectId - Identifies the subject whose attributes are read.
   * @param opts - Optional read options forwarded to fetch.
   * @returns The subject's attribute map.
   */
  async getSubjectAttributes(subjectId: string, opts?: Adapter.IReadOptions): Promise<Primitives.Attributes> {
    if (typeof subjectId !== 'string' || subjectId.length === 0 || subjectId.length > 1024) return {}
    const raw: unknown = await this._request(`/subjects/${encodeURIComponent(subjectId)}/attributes`, undefined, opts)
    return parseHttpSubjectAttributes(raw, subjectId)
  }
  /**
   * Shallow-merges new attributes into the subject's existing bag via PATCH.
   *
   * @param subjectId - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the API acknowledges the write.
   */
  async setSubjectAttributes(subjectId: string, attrs: Primitives.Attributes): Promise<void> {
    await this._request(`/subjects/${encodeURIComponent(subjectId)}/attributes`, {
      method: 'PATCH',
      body: JSON.stringify(attrs),
    })
  }
}

/** Read up to 200 chars of the response body for error messages. */
async function readBodyCapped(res: Response): Promise<string> {
  // Streaming read with a 4KB hard cap; `res.text()` would buffer the entire
  // body first - a hostile remote sending a multi-GB body would exhaust
  // memory before the cap-and-slice ever ran. We only need a short prefix
  // for the error-context line, so cap during ingest.
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
 * Stream-and-cap JSON reader: refuses bodies past 4 MiB so a hostile remote
 * cannot OOM us before we ever reach JSON.parse. Real IAM payloads are
 * <100 KiB; 4 MiB is generous for bulk-policy fetches.
 */
async function readJsonCapped<T>(res: Response): Promise<T> {
  const MAX_BYTES = 4 * 1024 * 1024
  const reader = res.body?.getReader()
  if (!reader) {
    return (await res.json()) as T
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
  return JSON.parse(text) as T
}

function parseHttpSubjectAttributes(value: unknown, subjectId: string): Primitives.Attributes {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    const got = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value
    throw new Error(
      `[@gentleduck/iam:http] getSubjectAttributes for "${subjectId}" returned ${got} (expected JSON object)`,
    )
  }
  return value as Primitives.Attributes
}

function parseHttpSubjectRoles<TRole extends string>(value: unknown, subjectId: string): TRole[] {
  if (!Array.isArray(value)) {
    const got = value === null ? 'null' : typeof value
    throw new Error(`[@gentleduck/iam:http] getSubjectRoles for "${subjectId}" returned ${got} (expected JSON array)`)
  }
  const roles: TRole[] = []
  for (const entry of value) {
    if (typeof entry === 'string' && entry.length > 0) {
      roles.push(entry as TRole)
    }
  }
  return roles
}

function parseHttpSubjectScopedRoles<TRole extends string, TScope extends string>(
  value: unknown,
  subjectId: string,
): Request.IScopedRole<TRole, TScope>[] {
  if (!Array.isArray(value)) {
    const got = value === null ? 'null' : typeof value
    throw new Error(
      `[@gentleduck/iam:http] getSubjectScopedRoles for "${subjectId}" returned ${got} (expected JSON array)`,
    )
  }
  const out: Request.IScopedRole<TRole, TScope>[] = []
  for (const entry of value) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue
    const role = Reflect.get(entry, 'role')
    const scope = Reflect.get(entry, 'scope')
    if (typeof role !== 'string' || role.length === 0) continue
    if (typeof scope !== 'string' || scope.length === 0) continue
    out.push({ role: role as TRole, scope: scope as TScope })
  }
  return out
}
