/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import { randomToken, sha256 } from '../crypto'
import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'

/**
 * JwtTransport - stateless transport for edge / serverless deployments.
 * Verifies tokens locally via HMAC so resolveSession() avoids a store hit
 * on the hot path. v0.1 ships HS256 only (Node built-in); EdDSA / ES256 /
 * RS256 land in v0.2 via `jose` so JWKS + key rotation are first-class.
 *
 * Token shape: standard JWT `<header>.<payload>.<sig>` base64url-encoded.
 * Header always `{ alg: 'HS256', typ: 'JWT', kid? }`.
 *
 * Refresh tokens are issued as opaque cookies (the persisted half of the
 * dual transport) and rotated server-side. Reuse detection at refresh
 * time follows the same family-id mechanism as OAuth refresh tokens.
 */
export interface JwtVerifyKey {
  kid: string
  /** HS256 secret (UTF-8 string). */
  key: string
  /** Optional rotation cutoff - verify-only after this. */
  notAfter?: number
}

export interface JwtTransportConfig {
  /** Active signing key. Used for every issued JWT until rotation. */
  signKey: { kid: string; key: string }
  /**
   * All currently-valid verify keys. Must contain `signKey`; during rotation,
   * the previous keys remain here for an overlap window so already-issued
   * tokens keep verifying.
   */
  verifyKeys: JwtVerifyKey[]
  issuer: string
  audience?: string
  /** JWT TTL in ms. Default 15 minutes. */
  ttlMs?: number
  /** Optional refresh cookie shape. */
  refresh?: {
    /** Cookie name carrying the opaque refresh token. */
    cookieName?: string
    /** Refresh TTL in ms. Default 7 days. */
    ttlMs?: number
  }
}

const DEFAULT_REFRESH_COOKIE = '__Host-duck-refresh'

interface JwtPayload {
  /** Issuer. */
  iss: string
  /** Subject - identity id. */
  sub: string | null
  /** Audience (optional). */
  aud?: string
  /** Issued-at, seconds. */
  iat: number
  /** Expiry, seconds. */
  exp: number
  /** Session id (hashed row key). */
  sid: string
  /** Session AAL. */
  aal: Session.AAL
  /** Session factors (method names only). */
  factors: string[]
  /** Tenant id when present. */
  tid?: string
  /** Acting-as envelope when impersonating. */
  acting_as?: Session.ActingAs
}

function base64urlEncode(s: string | Buffer): string {
  return (typeof s === 'string' ? Buffer.from(s) : s).toString('base64url')
}

function base64urlDecode(s: string): string {
  return Buffer.from(s, 'base64url').toString('utf8')
}

function hmacSign(key: string, signingInput: string): string {
  return createHmac('sha256', key).update(signingInput).digest('base64url')
}

export class JwtTransport implements Transport.ITransport {
  private readonly _verifyKeys: Map<string, JwtVerifyKey>
  private readonly _ttlMs: number
  private readonly _refreshCookieName: string
  private readonly _refreshTtlMs: number
  private readonly _refreshEnabled: boolean

  constructor(private readonly _cfg: JwtTransportConfig) {
    this._verifyKeys = new Map(_cfg.verifyKeys.map((k) => [k.kid, k]))
    if (!this._verifyKeys.has(_cfg.signKey.kid)) {
      this._verifyKeys.set(_cfg.signKey.kid, { kid: _cfg.signKey.kid, key: _cfg.signKey.key })
    }
    this._ttlMs = _cfg.ttlMs ?? 15 * 60 * 1000
    this._refreshEnabled = Boolean(_cfg.refresh)
    this._refreshCookieName = _cfg.refresh?.cookieName ?? DEFAULT_REFRESH_COOKIE
    this._refreshTtlMs = _cfg.refresh?.ttlMs ?? 7 * 24 * 60 * 60 * 1000
  }

  /** Pull the Bearer access token (header form preferred; cookie fallback for refresh). */
  extract(req: { headers: Headers }): string | null {
    const auth = req.headers.get('authorization')
    if (auth?.startsWith('Bearer ')) {
      const token = auth.slice('Bearer '.length).trim()
      if (token) return token
    }
    return null
  }

  /**
   * Issue an access JWT plus (when refresh enabled) an opaque refresh
   * cookie. The plaintext SID is used as the refresh cookie value so
   * the framework adapter can read it back at refresh time.
   */
  issue(sid: string, session: Session.ISession, _opts: Transport.IssueOpts): Provider.Intent[] {
    const now = Math.floor(Date.now() / 1000)
    const exp = Math.min(now + Math.floor(this._ttlMs / 1000), Math.floor(session.expiresAt / 1000))
    const headerObj: { alg: 'HS256'; typ: 'JWT'; kid: string } = {
      alg: 'HS256',
      typ: 'JWT',
      kid: this._cfg.signKey.kid,
    }
    const payload: JwtPayload = {
      iss: this._cfg.issuer,
      sub: session.identityId,
      iat: now,
      exp,
      sid: session.id,
      aal: session.aal,
      factors: session.factors.map((f) => f.method),
      ...(this._cfg.audience !== undefined && { aud: this._cfg.audience }),
      ...(session.tenantId !== undefined && { tid: session.tenantId }),
      ...(session.actingAs !== undefined && { acting_as: session.actingAs }),
    }
    const headerB64 = base64urlEncode(JSON.stringify(headerObj))
    const payloadB64 = base64urlEncode(JSON.stringify(payload))
    const signingInput = `${headerB64}.${payloadB64}`
    const sig = hmacSign(this._cfg.signKey.key, signingInput)
    const jwt = `${signingInput}.${sig}`

    const intents: Provider.Intent[] = [
      {
        type: 'json',
        status: 200,
        body: { access_token: jwt, expires_in: exp - now, token_type: 'Bearer' },
      },
    ]
    if (this._refreshEnabled) {
      const expiresInSec = Math.floor(this._refreshTtlMs / 1000)
      intents.unshift({
        type: 'setCookie',
        name: this._refreshCookieName,
        value: sid,
        options: {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          path: '/',
          maxAge: expiresInSec,
        },
      })
    }
    return intents
  }

  /** Revoke the refresh cookie (when in use); no-op for the stateless JWT. */
  revoke(): Provider.Intent[] {
    if (!this._refreshEnabled) {
      return [{ type: 'json', status: 200, body: { revoked: true } }]
    }
    return [
      {
        type: 'clearCookie',
        name: this._refreshCookieName,
        options: { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 },
      },
    ]
  }

  /** Verify the JWT and reconstruct a Session WITHOUT a store hit. */
  async verify(token: string): Promise<Session.ISession | null> {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const [headerB64, payloadB64, sig] = parts as [string, string, string]

    let header: { alg?: string; kid?: string; typ?: string }
    try {
      header = JSON.parse(base64urlDecode(headerB64))
    } catch {
      return null
    }
    if (header.alg !== 'HS256' || header.typ !== 'JWT' || !header.kid) return null

    const key = this._verifyKeys.get(header.kid)
    if (!key) return null
    if (key.notAfter !== undefined && key.notAfter < Date.now()) return null

    const expected = hmacSign(key.key, `${headerB64}.${payloadB64}`)
    const a = Buffer.from(sig)
    const b = Buffer.from(expected)
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null

    let payload: JwtPayload
    try {
      payload = JSON.parse(base64urlDecode(payloadB64))
    } catch {
      return null
    }
    const nowSec = Math.floor(Date.now() / 1000)
    if (payload.exp < nowSec) return null
    if (payload.iss !== this._cfg.issuer) return null
    if (this._cfg.audience !== undefined && payload.aud !== this._cfg.audience) return null

    const session: Session.ISession = {
      id: payload.sid,
      identityId: payload.sub,
      kind: payload.sub ? 'user' : 'guest',
      aal: payload.aal,
      factors: payload.factors.map((m) => ({ method: m as Session.FactorMethod, completedAt: payload.iat * 1000 })),
      createdAt: payload.iat * 1000,
      rotatedAt: payload.iat * 1000,
      expiresAt: payload.exp * 1000,
      absoluteExpiresAt: payload.exp * 1000,
      fresh: true,
    }
    if (payload.tid !== undefined) session.tenantId = payload.tid
    if (payload.acting_as !== undefined) session.actingAs = payload.acting_as
    return session
  }

  /**
   * Helper to mint a JWKS-style document for clients that need to verify
   * tokens out-of-band. v0.1 HS256 only - JWKS isn't applicable to
   * symmetric keys; this returns an empty `{ keys: [] }` placeholder.
   * EdDSA / RS256 in v0.2 will populate this with public keys.
   */
  jwks(): { keys: unknown[] } {
    return { keys: [] }
  }

  /**
   * Mint a fresh JWT from a session without rotating the SID. Used by
   * refresh endpoints after verifying the refresh cookie.
   */
  static mintFresh(transport: JwtTransport, sid: string, session: Session.ISession): Provider.Intent[] {
    return transport.issue(sid, session, { fresh: true, absolute: false })
  }
}

// Re-export for parity with cookie/bearer transports.
export { randomToken, sha256 }
