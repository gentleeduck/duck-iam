/**
 * @packageDocumentation
 * OIDC discovery document generator + standard route handlers. Emits
 * the canonical `/.well-known/openid-configuration` body so apps that
 * issue JWT access tokens via `JwtTransport` look like an OIDC OP to
 * relying parties.
 *
 * The lib does NOT mount the route - framework adapters wire it; this
 * module ships the document shape + a JWKS pass-through.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../core/errors'

/**
 * Subset of `JwtTransport` the discovery generator depends on. Lets
 * the discovery module stay isolated from the transport import cycle.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface JwtTransportLike {
  jwks(): { keys: Array<Record<string, unknown>> }
}

/**
 * Caller-supplied config for the discovery document.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OidcDiscoveryConfig {
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
  /** OAuth2 scopes the server is willing to honor. */
  scopesSupported?: string[]
  /** Default `['code']`; add `'token'`/`'id_token'` to enable hybrid flows. */
  responseTypesSupported?: string[]
  /** Default `['authorization_code', 'refresh_token', 'client_credentials']`. */
  grantTypesSupported?: string[]
  /** Default `['public', 'pairwise']`. */
  subjectTypesSupported?: string[]
  /** Extra fields merged at the top level (for OIDC profiles or extensions). */
  extraClaims?: Record<string, unknown>
}

/**
 * Canonical OIDC discovery document shape. Loose to keep the surface
 * future-proof; required fields are explicit, extras are passthrough.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OidcDiscoveryDocument {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  end_session_endpoint: string
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

/**
 * Build the discovery document. Pass-through `extraClaims` lets apps
 * append OIDC profile fields (e.g. `request_object_signing_alg_values_supported`
 * for the JAR profile) without forking this module.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function buildOidcDiscovery(cfg: OidcDiscoveryConfig): OidcDiscoveryDocument {
  if (!cfg.issuer) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'buildOidcDiscovery requires a non-empty issuer',
    })
  }
  const issuer = cfg.issuer.replace(/\/$/, '')
  const prefix = cfg.prefix ?? '/auth'
  const jwks = cfg.jwksPath ?? '/.well-known/jwks.json'
  const algs = cfg.signingAlgs ?? ['HS256']
  const doc: OidcDiscoveryDocument = {
    issuer,
    authorization_endpoint: `${issuer}${prefix}/oauth/authorize`,
    token_endpoint: `${issuer}${prefix}/oauth/token`,
    userinfo_endpoint: `${issuer}${prefix}/oauth/userinfo`,
    jwks_uri: `${issuer}${jwks}`,
    end_session_endpoint: `${issuer}${prefix}/oauth/logout`,
    scopes_supported: cfg.scopesSupported ?? ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: cfg.responseTypesSupported ?? ['code'],
    grant_types_supported: cfg.grantTypesSupported ?? ['authorization_code', 'refresh_token', 'client_credentials'],
    subject_types_supported: cfg.subjectTypesSupported ?? ['public'],
    id_token_signing_alg_values_supported: algs,
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    ...(cfg.extraClaims ?? {}),
  }
  return doc
}

/**
 * Express / Hono / Fastify / Koa friendly handler builder. Returns a
 * factory that produces the JSON body + a JWKS body the adapter can
 * mount under `/.well-known/jwks.json` directly.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function buildOidcRoutes(opts: { config: OidcDiscoveryConfig; transport: JwtTransportLike }): {
  discovery: OidcDiscoveryDocument
  jwks: { keys: Array<Record<string, unknown>> }
} {
  const discovery = buildOidcDiscovery(opts.config)
  const jwks = opts.transport.jwks()
  return { discovery, jwks }
}

/**
 * Namespace merge for the discovery surface.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace OidcDiscovery {
  /** Alias for `OidcDiscoveryConfig`. */
  export type IConfig = OidcDiscoveryConfig
  /** Alias for `OidcDiscoveryDocument`. */
  export type IDocument = OidcDiscoveryDocument
  /** Alias for `JwtTransportLike`. */
  export type IJwtTransport = JwtTransportLike
}
