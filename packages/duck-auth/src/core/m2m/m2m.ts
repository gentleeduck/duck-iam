/** The OAuth 2.0 `client_credentials` grant over the api-key store, so a service account mints JWT
 *  access tokens without user interaction. Credentials live in `Credential.kind = 'api-key'`, which
 *  is what lets `ApiKeysFacet` power lookup and rotation. */

import type { Limiter } from '~/limiters'
import { type ApiKeysFacet, isScopeToken } from '~/providers/api-key'
import { AuthError } from '../errors'
import { refuseRateLimited } from '../events/events.lockout'
import type { Provider } from '../provider/provider.types'
import type { SessionsImpl } from '../sessions/sessions'
import type { Transport } from '../transport/transport.types'
import {
  DEFAULT_M2M_CONFIG,
  M2M_CLIENT_FIELD_MAX_LENGTH,
  M2M_SCOPE_MAX_LENGTH,
  M2M_SCOPE_MAX_TOKENS,
  M2M_TTL_MAX_MS,
  M2M_TTL_MIN_MS,
} from './m2m.constants'
import type { M2m } from './m2m.types'

/**
 * Wires `ApiKeysFacet`, `SessionsImpl` and a transport together. Mount a `/oauth/token` route that
 * calls `exchange()` on `{ grant_type: 'client_credentials', client_id, client_secret, scope }`.
 *
 * WARN: the access token is a stateless JWT good until its `exp`, so revoking the api-key stops only
 * future exchanges. For prompt revocation shorten `ttlMs`, wire a JTI denylist, or introspect.
 */
export class M2MImpl {
  constructor(
    private readonly _apiKeys: ApiKeysFacet,
    private readonly _sessions: SessionsImpl,
    private readonly _transport: Transport.ITransport,
    private readonly _limiter: Limiter.Me,
    private readonly _cfg: M2m.Cfg = DEFAULT_M2M_CONFIG,
  ) {
    if (!Number.isFinite(_cfg.ttlMs) || _cfg.ttlMs < M2M_TTL_MIN_MS || _cfg.ttlMs > M2M_TTL_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `m2m: ttlMs must be a finite number between ${M2M_TTL_MIN_MS} and ${M2M_TTL_MAX_MS}`,
      })
    }
  }

  /** Run the exchange, answering with the standard OAuth 2.0 token envelope. Throws
   *  `AUTH_APIKEY_INVALID`, `AUTH_APIKEY_REVOKED` or `AUTH_APIKEY_SCOPE_INSUFFICIENT`. */
  async exchange(input: M2m.ExchangeInput): Promise<M2m.TokenResponse> {
    // Typed and bounded before anything hashes them: `authSha256` on a non-string throws a TypeError,
    // which is a 500 out of a path whose refusal is a 401, and it skips the quota below.
    if (typeof input.clientId !== 'string' || typeof input.clientSecret !== 'string') {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    if (!input.clientId || input.clientId.length > M2M_CLIENT_FIELD_MAX_LENGTH) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    if (!input.clientSecret || input.clientSecret.length > M2M_CLIENT_FIELD_MAX_LENGTH) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    // SECURITY: keyed on the client being attacked, not on the secret presented. A brute force sends a
    // different secret every time, so a per-secret key hands every guess a fresh budget and bounds
    // nothing. No bus: `refuseRateLimited` emits `lockout` only for a known identity, and this refusal
    // happens before the secret is verified, so there is none.
    const limited = await this._limiter.consume(`m2m:${input.clientId}`)
    if (!limited.ok) await refuseRateLimited(null, limited, null)
    const tenant = input.tenantId !== undefined ? { tenantId: input.tenantId } : {}
    const verified = await this._apiKeys.verify(input.clientSecret, tenant)
    if (verified.keyId !== input.clientId) {
      // The pair must agree, or a valid secret tied to a different client_id would pass.
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    // Refuses cross-tenant minting; an omitted tenantId falls back to the credential's own so `tid` is right.
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

  /** A transport is only found misconfigured after the session is written, so the row goes with it, or
   *  every rejected exchange leaves behind a session no token was issued for. */
  private async _abandon(sessionId: string, detail: string): Promise<never> {
    // Through `orNull`: a session already gone must not replace the misconfiguration below with its own code.
    await this._sessions.revokeByHash(sessionId).orNull()
    throw new AuthError('AUTH_MISCONFIGURED', { detail })
  }

  /** Intersect / strict mode for the requested -> granted scope mapping. */
  private _resolveScopes(requested: string[], have: string[]): string[] {
    if (requested.length === 0) return [...new Set(have)]
    if (this._cfg.scopeMode === 'intersect') {
      const granted = requested.filter((s) => have.includes(s))
      // RFC 6749 section 3.3 offers the server two answers, fail or issue the scopes it is willing
      // to grant. A token carrying an empty scope claim is neither, and leaves the resource server
      // to decide what a scopeless bearer token means, and that ambiguity resolves to an allow.
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

/** Validate the transport's emitted intent body, whose type is `unknown`. A non-finite `expires_in`
 *  would reach the client as `NaN`, and `Date.now() + NaN * 1000` is a token that never expires. */
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

export function m2m(
  apiKeys: ApiKeysFacet,
  sessions: SessionsImpl,
  transport: Transport.ITransport,
  limiter: Limiter.Me,
  cfg: M2m.Cfg,
): M2MImpl {
  return new M2MImpl(apiKeys, sessions, transport, limiter, cfg)
}
