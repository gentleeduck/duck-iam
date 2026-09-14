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

import { type ApiKeysFacet, isScopeToken } from '~/providers/api-key'
import { AuthError } from '../errors'
import type { Provider } from '../provider/provider.types'
import type { SessionsImpl } from '../sessions/sessions'
import type { Transport } from '../transport/transport.types'
import {
  DEFAULT_M2M_CONFIG,
  M2M_SCOPE_MAX_LENGTH,
  M2M_SCOPE_MAX_TOKENS,
  M2M_TTL_MAX_MS,
  M2M_TTL_MIN_MS,
} from './m2m.constants'
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
export class M2MImpl {
  constructor(
    private readonly _apiKeys: ApiKeysFacet,
    private readonly _sessions: SessionsImpl,
    private readonly _transport: Transport.ITransport,
    private readonly _cfg: M2m.Cfg = DEFAULT_M2M_CONFIG,
  ) {
    if (!Number.isFinite(_cfg.ttlMs) || _cfg.ttlMs < M2M_TTL_MIN_MS || _cfg.ttlMs > M2M_TTL_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `m2m: ttlMs must be a finite number between ${M2M_TTL_MIN_MS} and ${M2M_TTL_MAX_MS}`,
      })
    }
  }

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

    // An absent `scope` is "no opinion, grant what the key holds". A present one is a request, and a
    // request naming nothing is not the same thing: reading `scope=` as absence handed a client
    // every scope on the key when it had explicitly asked for none.
    let requested: string[] = []
    if (input.scope !== undefined) {
      if (typeof input.scope !== 'string' || input.scope.length > M2M_SCOPE_MAX_LENGTH) {
        throw new AuthError('AUTH_INVALID_CREDENTIALS')
      }
      // Deduplicate before the cap is counted, or sixty-four copies of one scope exhaust the budget
      // and push out the scopes that follow them in the same request.
      requested = [...new Set(input.scope.split(/\s+/).filter(Boolean))]
      if (requested.length === 0 || requested.length > M2M_SCOPE_MAX_TOKENS) {
        throw new AuthError('AUTH_INVALID_CREDENTIALS')
      }
      if (!requested.every(isScopeToken)) {
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
      factors: [{ method: 'api-key', completedAt: new Date(now) }],
      // A ceiling, never an extension, so the row expires with the token it was minted for. Nobody
      // ever signs out of an m2m session, so a row outliving its token is a row nothing will ever
      // remove; capped, the ordinary expiry sweep collects it.
      maxExpiresAt: new Date(now + this._cfg.ttlMs),
      ...(effectiveTenantId !== undefined && { tenantId: effectiveTenantId }),
    })
    // Project granted scope onto the JWT or `scopeMode: intersect` is wire-noop.
    const intents = this._transport.issue(sid, session, {
      fresh: true,
      absolute: false,
      scope: granted.join(' '),
    })
    const jsonIntent = intents.find((i): i is Extract<Provider.Intent, { type: 'json' }> => i.type === 'json')
    if (!jsonIntent) {
      return this._abandon(
        session.id,
        'M2MFacet requires JwtTransport (or equivalent) - cookie transports do not work here',
      )
    }
    // Validate body shape; transport must emit `{access_token, expires_in?}`.
    const parsedBody = parseM2MBody(jsonIntent.body)
    if (!parsedBody) {
      return this._abandon(session.id, 'transport did not emit an access_token; check JwtTransport config')
    }
    // Read back what the session actually got rather than recomputing from `ttlMs`: the sessions
    // facet's own ttl may be the shorter of the two, and reporting the configured one then
    // overstates the lifetime of a token that is already going to be refused sooner.
    const expiresIn = Math.max(0, Math.floor((session.expiresAt.getTime() - now) / 1000))
    return {
      access_token: parsedBody.access_token,
      token_type: 'Bearer',
      // A transport may cap a token shorter than the m2m policy; it can never extend one past it.
      expires_in: Math.min(parsedBody.expires_in ?? expiresIn, expiresIn),
      scope: granted.join(' '),
    }
  }

  /**
   * A transport is only found to be misconfigured after the session has been written, and leaving
   * the row behind let every rejected exchange against a wrongly wired transport persist a session
   * no token was ever issued for.
   */
  private async _abandon(sessionId: string, detail: string): Promise<never> {
    await this._sessions.revokeByHash(sessionId)
    throw new AuthError('AUTH_MISCONFIGURED', { detail })
  }

  /** Intersect / strict mode for the requested -> granted scope mapping. */
  private _resolveScopes(requested: string[], have: string[]): string[] {
    if (requested.length === 0) return [...new Set(have)]
    if (this._cfg.scopeMode === 'intersect') {
      const granted = requested.filter((s) => have.includes(s))
      // RFC 6749 section 3.3 offers the server two answers, fail or issue the scopes it is willing
      // to grant. A token carrying an empty scope claim is neither, and leaves the resource server
      // to decide what a scopeless bearer token means - the ambiguity that resolves to an allow.
      if (granted.length === 0) {
        throw new AuthError('AUTH_APIKEY_SCOPE_INSUFFICIENT', { required: requested, missing: requested })
      }
      return granted
    }
    const missing = requested.filter((s) => !have.includes(s))
    if (missing.length > 0) {
      // `missing` names back only scopes the caller already asked for. Reporting `have` told a
      // caller probing with one scope every other scope the key holds.
      throw new AuthError('AUTH_APIKEY_SCOPE_INSUFFICIENT', { required: requested, missing })
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

/** Factory for {@link M2MImpl}. */
export function m2m(
  apiKeys: ApiKeysFacet,
  sessions: SessionsImpl,
  transport: Transport.ITransport,
  cfg: M2m.Cfg,
): M2MImpl {
  return new M2MImpl(apiKeys, sessions, transport, cfg)
}
