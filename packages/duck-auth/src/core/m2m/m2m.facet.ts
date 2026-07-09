/**
 * Machine-to-machine (M2M) grant facet. Implements the oauth 2.0
 * `client_credentials` grant against the existing api-key store so
 * service accounts can mint JWT access tokens with the supplied
 * scopes without user interaction.
 *
 * Storage shape: client credentials are kept in `Credential.kind =
 * 'api-key'` (so the existing ApiKeysFacet powers lookup + rotation).
 * The grant verifies `client_id`+`client_secret`, mints a JWT via the
 * supplied JwtTransport, and returns the standard
 * `{ access_token, token_type, expires_in, scope }` token envelope.
 */

import type { ApiKeysFacet } from '~/providers/api-key/api-key.facet'
import { AuthError } from '../errors'
import type { Provider } from '../provider/provider.types'
import type { SessionsFacet } from '../sessions/sessions.facet'
import type { Session } from '../sessions/sessions.types'
import type { Transport } from '../types/session'
import { DEFAULT_M2M_CONFIG } from './m2m.constants'
import type { M2m } from './m2m.types'

/**
 * M2M facet. Wires the existing `ApiKeysFacet` + `SessionsFacet` +
 * `Transport.ITransport` together. Caller mounts a `/oauth/token`
 * route that calls `exchange()` on a body shaped like
 * `{ grant_type:'client_credentials', client_id, client_secret, scope }`.
 *
 * **Revocation latency.** The issued access token is a stateless JWT
 * good until its `exp`. Revoking the api-key only stops *future*
 * exchanges; tokens issued during the prior `cfg.ttlMs` window (default
 * 1h) keep verifying. For promptly-revocable tokens, shorten `ttlMs`,
 * or wire a JTI denylist via a custom transport, or front the resource
 * server with a token-introspection step.
 */
export class M2MFacet {
  constructor(
    private readonly _apiKeys: ApiKeysFacet,
    private readonly _sessions: SessionsFacet,
    private readonly _transport: Transport.ITransport,
    private readonly _cfg: M2m.Config = DEFAULT_M2M_CONFIG,
  ) {}

  /**
   * Run the client_credentials exchange. Returns the standard oauth2
   * token envelope on success; throws AUTH/APIKEY_INVALID /
   * AUTH/APIKEY_REVOKED / AUTH/APIKEY_SCOPE_INSUFFICIENT on failure.
   */
  async exchange(input: M2m.ExchangeInput): Promise<M2m.TokenResponse> {
    if (!input.clientId || !input.clientSecret) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    const tenant = input.tenantId !== undefined ? { tenantId: input.tenantId } : {}
    const verified = await this._apiKeys.verify(input.clientSecret, tenant)
    if (verified.keyId !== input.clientId) {
      // Plaintext + id pair must agree (defense against caller passing
      // a valid secret tied to a different client_id).
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    // Refuse cross-tenant token minting; if caller omits tenantId,
    // fall back to the credential's own so `tid` is correct.
    if (input.tenantId !== undefined && verified.tenantId !== undefined && input.tenantId !== verified.tenantId) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    const effectiveTenantId = input.tenantId ?? verified.tenantId

    // Cap scope (4KB / 64 tokens) before split since it's attacker-controllable.
    let requested: string[] = []
    if (input.scope) {
      if (typeof input.scope !== 'string' || input.scope.length > 4096) {
        throw new AuthError('AUTH_INVALID_CREDENTIALS')
      }
      requested = input.scope.split(/\s+/).filter(Boolean)
      if (requested.length > 64) {
        throw new AuthError('AUTH_INVALID_CREDENTIALS')
      }
    }
    const granted = this._resolveScopes(requested, verified.scopes)

    // Mint a service-account session; transport.issue produces the JWT.
    const now = Date.now()
    const { session, sid } = await this._sessions.create({
      identityId: verified.identityId,
      kind: 'apikey',
      aal: 1,
      factors: [{ method: 'api-key', completedAt: new Date() }],
      ...(effectiveTenantId !== undefined && { tenantId: effectiveTenantId }),
    })
    // Cap the session's expiry at the M2M ttl so the issued JWT lifetime
    // tracks the configured M2M policy rather than the SessionsFacet default.
    const sessionExpiresMs =
      session.expiresAt instanceof Date ? session.expiresAt.getTime() : (session.expiresAt as number)
    const issuedSession: Session.Me = {
      ...session,
      expiresAt: new Date(Math.min(sessionExpiresMs, now + this._cfg.ttlMs)),
    }
    // Project granted scope onto the JWT or `scopeMode: intersect` is wire-noop.
    const intents = this._transport.issue(sid, issuedSession, {
      fresh: true,
      absolute: false,
      scope: granted.join(' '),
    })
    const jsonIntent = intents.find((i): i is Extract<Provider.Intent, { type: 'json' }> => i.type === 'json')
    if (!jsonIntent) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'M2MFacet requires JwtTransport (or equivalent) - cookie transports do not work here',
      })
    }
    // Validate body shape; transport must emit `{access_token, expires_in?}`.
    const parsedBody = parseM2MBody(jsonIntent.body)
    if (!parsedBody) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'transport did not emit an access_token; check JwtTransport config',
      })
    }
    return {
      access_token: parsedBody.access_token,
      token_type: 'Bearer',
      expires_in: parsedBody.expires_in ?? Math.floor(this._cfg.ttlMs / 1000),
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
      throw new AuthError('AUTH_APIKEY_SCOPE_INSUFFICIENT', {
        required: requested,
        have,
      })
    }
    return requested
  }
}

/**
 * validate the transport's emitted JSON intent body shape without
 * an `as { access_token?, expires_in? }` cast. The body comes from a
 * transport's `issue()` return - in practice JwtTransport - but the
 * type is `unknown`. A non-finite `expires_in` would propagate `NaN`
 * into the client-credentials response and downstream
 * `Date.now() + expires_in * 1000` clients would see never-expiring
 * tokens; reject up-front.
 */
function parseM2MBody(raw: unknown): { access_token: string; expires_in?: number } | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  if (!('access_token' in raw)) return null
  const accessToken = raw.access_token
  if (typeof accessToken !== 'string' || accessToken.length === 0) return null
  const expiresInRaw = 'expires_in' in raw ? raw.expires_in : undefined
  if (expiresInRaw !== undefined && (typeof expiresInRaw !== 'number' || !Number.isFinite(expiresInRaw))) return null
  const out: { access_token: string; expires_in?: number } = { access_token: accessToken }
  if (expiresInRaw !== undefined) out.expires_in = expiresInRaw
  return out
}
