/** OIDC discovery-doc + JWKS helper. For the full OP, see `@gentleduck/auth/oidc/op`. */

import { isProduction } from '../core/env'
import { AuthError } from '../core/errors'
import { withoutTrailingSlashes } from '../core/url-validators'

/** How long the discovery request may take, its body included, unless `timeoutMs` says otherwise. */
const DISCOVERY_TIMEOUT_DEFAULT_MS = 10_000
/** Far past any real discovery document, which runs to a few KiB. */
const DISCOVERY_MAX_BYTES = 64 * 1024

/** Build the discovery document; `extraClaims` is appended verbatim. */
export function authBuildOidcDiscovery(cfg: AuthOidcDiscovery.Cfg): AuthOidcDiscovery.IDocument {
  if (!cfg.issuer) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'authBuildOidcDiscovery requires a non-empty issuer',
    })
  }
  // HTTPS, or plain http outside production (OIDC core 16.18); normalised so the issuer claim matches the
  // RP's computation.
  let parsed: URL
  try {
    parsed = new URL(cfg.issuer)
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authBuildOidcDiscovery: issuer '${cfg.issuer}' is not a valid URL`,
    })
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && !isProduction())) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authBuildOidcDiscovery: issuer must use HTTPS (${parsed.protocol}); plain http is admitted only outside production`,
    })
  }
  const canonicalPath = withoutTrailingSlashes(parsed.pathname)
  const issuer = `${parsed.origin}${canonicalPath}`
  const prefix = withoutTrailingSlashes(cfg.prefix ?? '/auth')
  const jwks = cfg.jwksPath ?? '/.well-known/jwks.json'
  // Appended to the issuer as text, so a path without its leading slash lands on another host.
  for (const [key, path] of [
    ['prefix', prefix],
    ['jwksPath', jwks],
  ] as const) {
    if (path.length > 0 && !path.startsWith('/')) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `authBuildOidcDiscovery: ${key} must start with / (got ${path})`,
      })
    }
  }
  const algs = cfg.signingAlgs ?? ['HS256']
  // SECURITY: an RP that picks its algorithm from this list will accept an unsigned id_token when `none` is
  // in it (OIDC Core 16.18). The union type forbids it; config parsed at runtime does not.
  for (const alg of algs) {
    if (alg.toLowerCase() === 'none') {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail:
          'authBuildOidcDiscovery: signingAlgs must not contain "none"; an RP reading it may accept an unsigned id_token',
      })
    }
  }
  // Spread `extraClaims` first so canonical fields cannot be shadowed.
  const doc: AuthOidcDiscovery.IDocument = {
    ...(cfg.extraClaims ?? {}),
    issuer,
    authorization_endpoint: `${issuer}${prefix}/oauth/authorize`,
    token_endpoint: `${issuer}${prefix}/oauth/token`,
    userinfo_endpoint: `${issuer}${prefix}/oauth/userinfo`,
    jwks_uri: `${issuer}${jwks}`,
    end_session_endpoint: `${issuer}${prefix}/oauth/logout`,
    introspection_endpoint: `${issuer}${prefix}/oauth/introspect`,
    revocation_endpoint: `${issuer}${prefix}/oauth/revoke`,
    ...(cfg.registrationEndpoint !== undefined && { registration_endpoint: cfg.registrationEndpoint }),
    scopes_supported: cfg.scopesSupported ?? ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: cfg.responseTypesSupported ?? ['code'],
    grant_types_supported: cfg.grantTypesSupported ?? ['authorization_code', 'refresh_token', 'client_credentials'],
    subject_types_supported: cfg.subjectTypesSupported ?? ['public'],
    id_token_signing_alg_values_supported: algs,
    token_endpoint_auth_methods_supported: cfg.tokenEndpointAuthMethodsSupported ?? [
      'client_secret_basic',
      'client_secret_post',
    ],
    code_challenge_methods_supported: ['S256'],
  }
  return doc
}

/** Builds the discovery document and the transport's JWKS as of this call, for a host to serve as JSON. */
export function authBuildOidcRoutes(opts: {
  config: AuthOidcDiscovery.Cfg
  transport: AuthOidcDiscovery.IJwtTransport
}): {
  discovery: AuthOidcDiscovery.IDocument
  jwks: { keys: Array<Record<string, unknown>> }
} {
  const discovery = authBuildOidcDiscovery(opts.config)
  const jwks = opts.transport.jwks()
  return { discovery, jwks }
}

/** RP-side OIDC discovery fetcher; in-process LRU (TTL 1h, capacity 32); rejects plain http in production. */
export async function authFetchOidcDiscovery(
  issuer: string,
  opts: {
    fetch?: typeof globalThis.fetch
    ttlMs?: number
    /** Skip the cache lookup; still writes the result. Use for forced refresh. */
    bypassCache?: boolean
    /** How long the request may take, its body included. Default 10 seconds. */
    timeoutMs?: number
  } = {},
): Promise<AuthOidcDiscovery.IPublishedDocument> {
  let parsed: URL
  try {
    parsed = new URL(issuer)
  } catch {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery: issuer ${issuer} is not a valid URL`,
    })
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && !isProduction())) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery: issuer must use HTTPS (${parsed.protocol}); plain http is admitted only outside production`,
    })
  }
  const timeoutMs = opts.timeoutMs ?? DISCOVERY_TIMEOUT_DEFAULT_MS
  // `setTimeout`'s ceiling: past it the timer fires at once.
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authFetchOidcDiscovery: timeoutMs must be a number of milliseconds from 1 to 2147483647 (got ${String(timeoutMs)})`,
    })
  }
  const canonical = `${parsed.origin}${withoutTrailingSlashes(parsed.pathname)}`
  const cacheKey = canonical
  if (!opts.bypassCache) {
    const hit = _discoveryCache.get(cacheKey)
    if (hit && hit.expiresAt > Date.now()) return hit.doc
  }
  const fetchImpl = opts.fetch ?? globalThis.fetch
  const url = `${canonical}/.well-known/openid-configuration`
  let res: Response
  let raw: unknown
  try {
    // The signal bounds the body read as well as the response.
    res = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs) })
    raw = res.ok ? await readJsonCapped(res) : null
  } catch (err) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery ${url} unreachable: ${err instanceof Error ? err.message : String(err)}`,
    })
  }
  if (!res.ok) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery ${url} returned ${res.status}`,
    })
  }
  const doc = parseDiscoveryDoc(raw)
  if (!doc) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery ${url}: malformed discovery document, or one over ${DISCOVERY_MAX_BYTES} bytes`,
    })
  }
  // the upstream's `issuer` claim MUST equal the requested issuer
  // (RFC 8414 section 3.3). Defeats an attacker who can hijack the well-known
  // endpoint from redirecting RPs to an attacker-controlled JWKS.
  if (withoutTrailingSlashes(doc.issuer) !== canonical) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery: issuer mismatch (requested ${canonical}, got ${doc.issuer})`,
    })
  }
  const ttlMs = opts.ttlMs ?? _discoveryTtlMs
  _discoveryCache.set(cacheKey, { doc, expiresAt: Date.now() + ttlMs })
  // Evict over capacity (insertion-order LRU; Map preserves order).
  while (_discoveryCache.size > _discoveryCapacity) {
    const oldest = _discoveryCache.keys().next().value
    if (oldest === undefined) break
    _discoveryCache.delete(oldest)
  }
  return doc
}

/** The body parsed as JSON, read no further than {@link DISCOVERY_MAX_BYTES}: `null` past that, or when it is
 *  not JSON. A read that fails, a timeout included, throws. */
async function readJsonCapped(res: Response): Promise<unknown> {
  const reader = res.body?.getReader()
  if (!reader) return null
  const decoder = new TextDecoder()
  let text = ''
  let size = 0
  try {
    for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
      size += chunk.value.byteLength
      if (size > DISCOVERY_MAX_BYTES) return null
      text += decoder.decode(chunk.value, { stream: true })
    }
  } finally {
    void reader.cancel().catch(() => {})
  }
  try {
    return JSON.parse(text + decoder.decode())
  } catch {
    return null
  }
}

/** Structural validator for an OIDC discovery doc; `null` on any required-field shape mismatch. */
function parseDiscoveryDoc(raw: unknown): AuthOidcDiscovery.IPublishedDocument | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  const requireString = (key: string): string | null => {
    const v: unknown = Reflect.get(raw, key)
    return typeof v === 'string' && v.length > 0 ? v : null
  }
  const requireStringArray = (key: string): string[] | null => {
    const v: unknown = Reflect.get(raw, key)
    if (!Array.isArray(v)) return null
    const out: string[] = []
    for (const item of v) {
      if (typeof item !== 'string') return null
      out.push(item)
    }
    return out
  }
  /** The spec's default when absent, `null` when present and not a list of strings. */
  const arrayOr = (key: string, fallback: string[]): string[] | null =>
    Reflect.get(raw, key) === undefined ? fallback : requireStringArray(key)
  // Required only where OIDC Discovery 1.0 section 3 requires it: Google, Apple and Microsoft each omit an optional field.
  const issuer = requireString('issuer')
  const authorization_endpoint = requireString('authorization_endpoint')
  const token_endpoint = requireString('token_endpoint')
  const jwks_uri = requireString('jwks_uri')
  if (issuer === null || authorization_endpoint === null || token_endpoint === null || jwks_uri === null) {
    return null
  }
  // `openid` is the one scope every OP supports, and an issuer listing no PKCE method supports none (RFC 8414).
  const scopes_supported = arrayOr('scopes_supported', ['openid'])
  const response_types_supported = requireStringArray('response_types_supported')
  const grant_types_supported = arrayOr('grant_types_supported', ['authorization_code', 'implicit'])
  const subject_types_supported = requireStringArray('subject_types_supported')
  const id_token_signing_alg_values_supported = requireStringArray('id_token_signing_alg_values_supported')
  const token_endpoint_auth_methods_supported = arrayOr('token_endpoint_auth_methods_supported', [
    'client_secret_basic',
  ])
  const code_challenge_methods_supported = arrayOr('code_challenge_methods_supported', [])
  if (
    scopes_supported === null ||
    response_types_supported === null ||
    grant_types_supported === null ||
    subject_types_supported === null ||
    id_token_signing_alg_values_supported === null ||
    token_endpoint_auth_methods_supported === null ||
    code_challenge_methods_supported === null
  ) {
    return null
  }
  const out: AuthOidcDiscovery.IPublishedDocument = {
    issuer,
    authorization_endpoint,
    token_endpoint,
    jwks_uri,
    scopes_supported,
    response_types_supported,
    grant_types_supported,
    subject_types_supported,
    id_token_signing_alg_values_supported,
    token_endpoint_auth_methods_supported,
    code_challenge_methods_supported,
  }
  // Checked here, or the extras below copied a non-string into a field typed as one.
  for (const key of [
    'userinfo_endpoint',
    'end_session_endpoint',
    'introspection_endpoint',
    'revocation_endpoint',
    'registration_endpoint',
  ] as const) {
    if (Reflect.get(raw, key) === undefined) continue
    const v = requireString(key)
    if (v === null) return null
    out[key] = v
  }
  // Preserve unknown extras (extension fields, custom claims).
  for (const [k, v] of Object.entries(raw)) {
    if (!(k in out)) out[k] = v
  }
  return out
}

interface DiscoveryCacheEntry {
  doc: AuthOidcDiscovery.IPublishedDocument
  expiresAt: number
}
let _discoveryTtlMs = 60 * 60 * 1000
let _discoveryCapacity = 32
const _discoveryCache = new Map<string, DiscoveryCacheEntry>()

/**
 * Tune the RP-side discovery cache. Called once at boot; affects
 * every subsequent `authFetchOidcDiscovery` call across the process.
 */
export function authConfigureOidcDiscoveryCache(opts: { ttlMs?: number; capacity?: number }): void {
  // A NaN capacity never evicts, and a NaN ttlMs never caches.
  if (opts.ttlMs !== undefined && !(opts.ttlMs >= 0)) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authConfigureOidcDiscoveryCache: ttlMs must be a number of milliseconds, 0 or more (got ${String(opts.ttlMs)})`,
    })
  }
  if (opts.capacity !== undefined && !(Number.isSafeInteger(opts.capacity) && opts.capacity >= 0)) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authConfigureOidcDiscoveryCache: capacity must be a whole number, 0 or more (got ${String(opts.capacity)})`,
    })
  }
  if (opts.ttlMs !== undefined) _discoveryTtlMs = opts.ttlMs
  if (opts.capacity !== undefined) _discoveryCapacity = opts.capacity
}

/** @deprecated Misspelled; use {@link authConfigureOidcDiscoveryCache}. */
export const authCfgureOidcDiscoveryCache = authConfigureOidcDiscoveryCache

/** Drop every cached discovery doc; useful for tests + ops rotation. */
export function authFlushOidcDiscoveryCache(): void {
  _discoveryCache.clear()
}

/** The discovery document's options and shape. */
export namespace AuthOidcDiscovery {
  /** What the discovery document advertises. */
  export interface Cfg {
    /** Required. Public issuer URL (no trailing slash), HTTPS; plain http is admitted only outside production. */
    issuer: string
    /** Mount prefix for the auth routes; default `/auth`. */
    prefix?: string
    /**
     * Path to the JWKS endpoint your framework adapter exposes. Default
     * `/.well-known/jwks.json`.
     */
    jwksPath?: string
    /** Algorithms advertised. Should match the JwtTransport keys. */
    signingAlgs?: Array<'HS256' | 'ES256' | 'RS256'>
    /** oauth2 scopes the server is willing to honor. */
    scopesSupported?: string[]
    /** Default `['code']`; add `'token'`/`'id_token'` to enable hybrid flows. */
    responseTypesSupported?: string[]
    /** Default `['authorization_code', 'refresh_token', 'client_credentials']`. */
    grantTypesSupported?: string[]
    /** Default `['public']`. */
    subjectTypesSupported?: string[]
    /** Default `['client_secret_basic', 'client_secret_post']`; add `'none'` for PKCE-only public clients. */
    tokenEndpointAuthMethodsSupported?: string[]
    /**
     * Advertise a `registration_endpoint` (RFC 7591). Set when the
     * host wires `AuthOidcOP.register` on a public route. Omit to suppress
     * the field entirely.
     */
    registrationEndpoint?: string
    /**
     * Extra fields merged at the top level (for OIDC profiles or
     * extensions). Spread BEFORE the canonical fields so a misconfigured
     * caller cannot shadow `issuer`, `jwks_uri`, `token_endpoint`, etc.
     * via this hatch.
     */
    extraClaims?: Record<string, unknown>
  }

  /** A discovery document as an issuer publishes it, as `authFetchOidcDiscovery` answers it: an endpoint the spec
   *  leaves optional may be absent, and an absent list holds the spec's default. */
  export interface IPublishedDocument {
    issuer: string
    authorization_endpoint: string
    token_endpoint: string
    userinfo_endpoint?: string
    jwks_uri: string
    end_session_endpoint?: string
    introspection_endpoint?: string
    revocation_endpoint?: string
    registration_endpoint?: string
    scopes_supported: string[]
    response_types_supported: string[]
    grant_types_supported: string[]
    subject_types_supported: string[]
    id_token_signing_alg_values_supported: string[]
    token_endpoint_auth_methods_supported: string[]
    code_challenge_methods_supported: string[]
    [extra: string]: unknown
  }

  /** The `/.well-known/openid-configuration` document `authBuildOidcDiscovery` builds, every endpoint in it. */
  export interface IDocument extends IPublishedDocument {
    userinfo_endpoint: string
    end_session_endpoint: string
  }

  /** The JWT transport surface that publishes its verify keys. */
  export interface IJwtTransport {
    /** The public keys as a JWKS. */
    jwks(): { keys: Array<Record<string, unknown>> }
  }
}
