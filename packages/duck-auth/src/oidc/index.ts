/** OIDC discovery-doc + JWKS helper. For the full OP, see `@gentleduck/AUTH/oidc/op`. */

import { AuthError } from '../core/errors'

/** Build the discovery document; `extraClaims` is appended verbatim. */
export function authBuildOidcDiscovery(cfg: AuthOidcDiscovery.IConfig): AuthOidcDiscovery.IDocument {
  if (!cfg.issuer) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'authBuildOidcDiscovery requires a non-empty issuer',
    })
  }
  // Reject non-http(s) schemes; normalise so issuer claim matches RP computation
  // (OIDC core 16.18 requires HTTPS in production).
  let parsed: URL
  try {
    parsed = new URL(cfg.issuer)
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authBuildOidcDiscovery: issuer '${cfg.issuer}' is not a valid URL`,
    })
  }
  if (parsed.protocol !== 'https:' && !cfg.allowHttp) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authBuildOidcDiscovery: issuer must use HTTPS (${parsed.protocol}). Pass allowHttp: true for dev only.`,
    })
  }
  const canonicalPath = parsed.pathname.replace(/\/+$/, '')
  const issuer = `${parsed.origin}${canonicalPath}`
  const prefix = cfg.prefix ?? '/auth'
  const jwks = cfg.jwksPath ?? '/.well-known/jwks.json'
  const algs = cfg.signingAlgs ?? ['HS256']
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

/**
 * Express / Hono / Fastify / Koa friendly handler builder. Returns a
 * factory that produces the JSON body + a JWKS body the adapter can
 * mount under `/.well-known/jwks.json` directly.
 */
export function authBuildOidcRoutes(opts: {
  config: AuthOidcDiscovery.IConfig
  transport: AuthOidcDiscovery.IJwtTransport
}): {
  discovery: AuthOidcDiscovery.IDocument
  jwks: { keys: Array<Record<string, unknown>> }
} {
  const discovery = authBuildOidcDiscovery(opts.config)
  const jwks = opts.transport.jwks()
  return { discovery, jwks }
}

/** RP-side OIDC discovery fetcher; in-process LRU (TTL 1h, capacity 32); rejects non-HTTPS unless `allowHttp`. */
export async function authFetchOidcDiscovery(
  issuer: string,
  opts: {
    fetch?: typeof globalThis.fetch
    allowHttp?: boolean
    ttlMs?: number
    /** Skip the cache lookup; still writes the result. Use for forced refresh. */
    bypassCache?: boolean
  } = {},
): Promise<AuthOidcDiscovery.IDocument> {
  let parsed: URL
  try {
    parsed = new URL(issuer)
  } catch {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery: issuer ${issuer} is not a valid URL`,
    })
  }
  if (parsed.protocol !== 'https:' && !opts.allowHttp) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery: issuer must use HTTPS (${parsed.protocol}). Pass allowHttp: true for dev only.`,
    })
  }
  const canonical = `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`
  const cacheKey = canonical
  if (!opts.bypassCache) {
    const hit = _discoveryCache.get(cacheKey)
    if (hit && hit.expiresAt > Date.now()) return hit.doc
  }
  const fetchImpl = opts.fetch ?? globalThis.fetch
  const url = `${canonical}/.well-known/openid-configuration`
  const res = await fetchImpl(url, { redirect: 'error' })
  if (!res.ok) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery ${url} returned ${res.status}`,
    })
  }
  const raw: unknown = await res.json()
  const doc = parseDiscoveryDoc(raw)
  if (!doc) {
    throw new AuthError('AUTH_PROVIDER_FAILED', {
      providerId: 'oidc',
      detail: `authFetchOidcDiscovery ${url}: malformed discovery document`,
    })
  }
  // the upstream's `issuer` claim MUST equal the requested issuer
  // (RFC 8414 section 3.3). Defeats an attacker who can hijack the well-known
  // endpoint from redirecting RPs to an attacker-controlled JWKS.
  if (doc.issuer.replace(/\/+$/, '') !== canonical) {
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

/** Structural validator for an OIDC discovery doc; `null` on any required-field shape mismatch. */
function parseDiscoveryDoc(raw: unknown): AuthOidcDiscovery.IDocument | null {
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
  const issuer = requireString('issuer')
  const authorization_endpoint = requireString('authorization_endpoint')
  const token_endpoint = requireString('token_endpoint')
  const userinfo_endpoint = requireString('userinfo_endpoint')
  const jwks_uri = requireString('jwks_uri')
  const end_session_endpoint = requireString('end_session_endpoint')
  if (
    issuer === null ||
    authorization_endpoint === null ||
    token_endpoint === null ||
    userinfo_endpoint === null ||
    jwks_uri === null ||
    end_session_endpoint === null
  ) {
    return null
  }
  const scopes_supported = requireStringArray('scopes_supported')
  const response_types_supported = requireStringArray('response_types_supported')
  const grant_types_supported = requireStringArray('grant_types_supported')
  const subject_types_supported = requireStringArray('subject_types_supported')
  const id_token_signing_alg_values_supported = requireStringArray('id_token_signing_alg_values_supported')
  const token_endpoint_auth_methods_supported = requireStringArray('token_endpoint_auth_methods_supported')
  const code_challenge_methods_supported = requireStringArray('code_challenge_methods_supported')
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
  const reg: unknown = Reflect.get(raw, 'registration_endpoint')
  if (reg !== undefined && (typeof reg !== 'string' || reg.length === 0)) return null
  const out: AuthOidcDiscovery.IDocument = {
    issuer,
    authorization_endpoint,
    token_endpoint,
    userinfo_endpoint,
    jwks_uri,
    end_session_endpoint,
    scopes_supported,
    response_types_supported,
    grant_types_supported,
    subject_types_supported,
    id_token_signing_alg_values_supported,
    token_endpoint_auth_methods_supported,
    code_challenge_methods_supported,
  }
  if (typeof reg === 'string') out.registration_endpoint = reg
  // Preserve unknown extras (extension fields, custom claims).
  for (const [k, v] of Object.entries(raw)) {
    if (!(k in out)) out[k] = v
  }
  return out
}

interface DiscoveryCacheEntry {
  doc: AuthOidcDiscovery.IDocument
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
  if (opts.ttlMs !== undefined) _discoveryTtlMs = opts.ttlMs
  if (opts.capacity !== undefined) _discoveryCapacity = opts.capacity
}

/** Drop every cached discovery doc; useful for tests + ops rotation. */
export function authFlushOidcDiscoveryCache(): void {
  _discoveryCache.clear()
}

export namespace AuthOidcDiscovery {
  export interface IConfig {
    /** Required. Public issuer URL (no trailing slash). */
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
    /** Default `['public', 'pairwise']`. */
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
     * Permit a non-HTTPS `issuer`. Dev-only. OIDC core section 16.18 requires
     * HTTPS in production. Default false; explicit opt-in here so the
     * misconfig is visible in code review.
     */
    allowHttp?: boolean
    /**
     * Extra fields merged at the top level (for OIDC profiles or
     * extensions). Spread BEFORE the canonical fields so a misconfigured
     * caller cannot shadow `issuer`, `jwks_uri`, `token_endpoint`, etc.
     * via this hatch.
     */
    extraClaims?: Record<string, unknown>
  }

  export interface IDocument {
    issuer: string
    authorization_endpoint: string
    token_endpoint: string
    userinfo_endpoint: string
    jwks_uri: string
    end_session_endpoint: string
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

  export interface IJwtTransport {
    jwks(): { keys: Array<Record<string, unknown>> }
  }
}
