/**
 * @packageDocumentation
 * Machine-to-machine (M2M) grant facet. Implements the OAuth 2.0
 * `client_credentials` grant against the existing api-key store so
 * service accounts can mint JWT access tokens with the supplied
 * scopes without user interaction.
 *
 * Storage shape: client credentials are kept in `Credential.kind =
 * 'api-key'` (so the existing ApiKeysFacet powers lookup + rotation).
 * The grant verifies `client_id`+`client_secret`, mints a JWT via the
 * supplied JwtTransport, and returns the standard
 * `{ access_token, token_type, expires_in, scope }` token envelope.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'
import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'
import type { ApiKeysFacet } from './apikeys'
import type { SessionsFacet } from './sessions'

/**
 * Config knobs for `M2MFacet`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface M2MFacetConfig {
  /** Lifetime of the issued access token, ms. Default 1 hour. */
  ttlMs: number
  /**
   * When true, restrict the requested scopes to the intersection of
   * (requested, key.scopes); when false, refuse the grant when the key
   * lacks any requested scope. Default `'intersect'`.
   */
  scopeMode: 'intersect' | 'strict'
}

export const DEFAULT_M2M_CONFIG: M2MFacetConfig = {
  ttlMs: 60 * 60 * 1000,
  scopeMode: 'intersect',
}

/**
 * Input to {@link M2MFacet.exchange}. Mirrors the OAuth2 form-body
 * fields per RFC 6749 section 4.4.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface M2MExchangeInput {
  /** Plaintext client id; for duck-auth this is the api-key id surfaced at creation. */
  clientId: string
  /** Plaintext client secret; sha-256 hashed for lookup. */
  clientSecret: string
  /** Optional space-separated OAuth2 scope string. */
  scope?: string
  /** Tenant scope. */
  tenantId?: string
}

/**
 * Standard token-endpoint response shape per RFC 6749 section 5.1.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface M2MTokenResponse {
  access_token: string
  token_type: 'Bearer'
  expires_in: number
  scope: string
}

/**
 * M2M facet. Wires the existing `ApiKeysFacet` + `SessionsFacet` +
 * `Transport.ITransport` together. Caller mounts a `/oauth/token`
 * route that calls `exchange()` on a body shaped like
 * `{ grant_type:'client_credentials', client_id, client_secret, scope }`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class M2MFacet {
  constructor(
    private readonly _apiKeys: ApiKeysFacet,
    private readonly _sessions: SessionsFacet,
    private readonly _transport: Transport.ITransport,
    private readonly _cfg: M2MFacetConfig = DEFAULT_M2M_CONFIG,
  ) {}

  /**
   * Run the client_credentials exchange. Returns the standard OAuth2
   * token envelope on success; throws AUTH/APIKEY_INVALID /
   * AUTH/APIKEY_REVOKED / AUTH/APIKEY_SCOPE_INSUFFICIENT on failure.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async exchange(input: M2MExchangeInput): Promise<M2MTokenResponse> {
    if (!input.clientId || !input.clientSecret) {
      throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    }
    const tenant = input.tenantId !== undefined ? { tenantId: input.tenantId } : {}
    const verified = await this._apiKeys.verify(input.clientSecret, tenant)
    if (verified.keyId !== input.clientId) {
      // Plaintext + id pair must agree (defense against caller passing
      // a valid secret tied to a different client_id).
      throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    }

    const requested = input.scope ? input.scope.split(/\s+/).filter(Boolean) : []
    const granted = this._resolveScopes(requested, verified.scopes)

    // Mint a service-account session; transport.issue produces the JWT.
    const now = Date.now()
    const { session, sid } = await this._sessions.create({
      identityId: verified.identityId,
      kind: 'apikey',
      aal: 1,
      factors: [{ method: 'api-key', completedAt: now }],
      ...(input.tenantId !== undefined && { tenantId: input.tenantId }),
    })
    // Cap the session's expiry at the M2M ttl so the issued JWT lifetime
    // tracks the configured M2M policy rather than the SessionsFacet default.
    const issuedSession: Session.ISession = {
      ...session,
      expiresAt: Math.min(session.expiresAt, now + this._cfg.ttlMs),
    }
    const intents = this._transport.issue(sid, issuedSession, { fresh: true, absolute: false })
    const jsonIntent = intents.find((i): i is Extract<Provider.Intent, { type: 'json' }> => i.type === 'json')
    if (!jsonIntent) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'M2MFacet requires JwtTransport (or equivalent) - cookie transports do not work here',
      })
    }
    const body = jsonIntent.body as { access_token?: string; expires_in?: number }
    if (!body.access_token) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'transport did not emit an access_token; check JwtTransport config',
      })
    }
    return {
      access_token: body.access_token,
      token_type: 'Bearer',
      expires_in: body.expires_in ?? Math.floor(this._cfg.ttlMs / 1000),
      scope: granted.join(' '),
    }
  }

  /** Intersect / strict mode for the requested -> granted scope mapping. */
  private _resolveScopes(requested: string[], have: string[]): string[] {
    if (requested.length === 0) return have
    if (this._cfg.scopeMode === 'intersect') {
      return requested.filter((s) => have.includes(s))
    }
    const missing = requested.filter((s) => !have.includes(s))
    if (missing.length > 0) {
      throw new AuthErrorObject('AUTH/APIKEY_SCOPE_INSUFFICIENT', {
        required: requested,
        have,
      })
    }
    return requested
  }
}

/**
 * Namespace merge for `M2MFacet`. Co-locates config + IO shapes
 * alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace M2MFacet {
  /** Alias for `M2MFacetConfig`. */
  export type IConfig = M2MFacetConfig
  /** Alias for `M2MExchangeInput`. */
  export type IExchangeInput = M2MExchangeInput
  /** Alias for `M2MTokenResponse`. */
  export type ITokenResponse = M2MTokenResponse
}
