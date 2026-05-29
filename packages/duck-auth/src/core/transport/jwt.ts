/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createHmac, createPublicKey, createSign, createVerify, timingSafeEqual } from 'node:crypto'
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
/** Signature algorithms supported by `JwtTransport`. */
export type JwtAlg = 'HS256' | 'ES256' | 'RS256'

export interface JwtVerifyKey {
  kid: string
  /**
   * Algorithm this key verifies. Default `'HS256'` for backwards
   * compatibility; ES256 + RS256 callers must set this explicitly.
   */
  alg?: JwtAlg
  /**
   * Key material. For `HS256`: the UTF-8 secret. For `ES256` / `RS256`:
   * the PEM-encoded public key (SPKI or RSA-PUBLIC).
   */
  key: string
  /** Optional rotation cutoff - verify-only after this. */
  notAfter?: number
}

export interface JwtTransportConfig {
  /**
   * Active signing key. For HS256 the `key` is the secret; for ES256 /
   * RS256 it is the PEM-encoded PRIVATE key. `alg` defaults to HS256.
   */
  signKey: { kid: string; alg?: JwtAlg; key: string }
  /**
   * All currently-valid verify keys. Must contain `signKey`; during rotation,
   * the previous keys remain here for an overlap window so already-issued
   * tokens keep verifying.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
  /** Session kind (`'user' | 'apikey' | 'guest'`). Preserved so M2M tokens round-trip correctly. */
  knd?: Session.Kind
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

/** Sign per `alg`. Returns the base64url signature segment. */
function jwsSign(alg: JwtAlg, key: string, signingInput: string): string {
  if (alg === 'HS256') return hmacSign(key, signingInput)
  if (alg === 'RS256') {
    const signer = createSign('RSA-SHA256')
    signer.update(signingInput)
    signer.end()
    return signer.sign(key).toString('base64url')
  }
  // ES256: createSign emits DER; JOSE expects raw r||s.
  const signer = createSign('SHA256')
  signer.update(signingInput)
  signer.end()
  const der = signer.sign(key)
  return derToJoseEs256(der).toString('base64url')
}

/** Verify per `alg`. Returns true on match. */
function jwsVerify(alg: JwtAlg, key: string, signingInput: string, sigB64: string): boolean {
  if (alg === 'HS256') {
    const expected = hmacSign(key, signingInput)
    const a = Buffer.from(sigB64)
    const b = Buffer.from(expected)
    return a.length === b.length && timingSafeEqual(a, b)
  }
  const sig = Buffer.from(sigB64, 'base64url')
  if (alg === 'RS256') {
    const verifier = createVerify('RSA-SHA256')
    verifier.update(signingInput)
    verifier.end()
    return verifier.verify(key, sig)
  }
  // ES256: DPoP-style raw r||s -> DER for createVerify.
  const verifier = createVerify('SHA256')
  verifier.update(signingInput)
  verifier.end()
  try {
    return verifier.verify(key, joseToDerEs256(sig))
  } catch {
    return false
  }
}

/** Convert ES256 DER signature to raw r||s (64 bytes for P-256). */
function derToJoseEs256(der: Buffer): Buffer {
  const halfLen = 32
  if (der[0] !== 0x30) throw new Error('ES256 sig: not a DER sequence')
  let offset = 2
  if ((der[1] ?? 0) & 0x80) offset = 2 + ((der[1] ?? 0) & 0x7f)
  if (der[offset] !== 0x02) throw new Error('ES256 sig: expected r INTEGER')
  const rLen = der[offset + 1]!
  let r = der.subarray(offset + 2, offset + 2 + rLen)
  offset = offset + 2 + rLen
  if (der[offset] !== 0x02) throw new Error('ES256 sig: expected s INTEGER')
  const sLen = der[offset + 1]!
  let s = der.subarray(offset + 2, offset + 2 + sLen)
  if (r[0] === 0 && r.length === halfLen + 1) r = r.subarray(1)
  if (s[0] === 0 && s.length === halfLen + 1) s = s.subarray(1)
  return Buffer.concat([Buffer.alloc(halfLen - r.length), r, Buffer.alloc(halfLen - s.length), s])
}

/** Convert raw r||s ES256 signature to DER for Node's createVerify. */
function joseToDerEs256(raw: Buffer): Buffer {
  const halfLen = 32
  if (raw.length !== halfLen * 2) throw new Error('ES256 sig: bad length')
  let r = raw.subarray(0, halfLen)
  let s = raw.subarray(halfLen)
  while (r.length > 1 && r[0] === 0) r = r.subarray(1)
  while (s.length > 1 && s[0] === 0) s = s.subarray(1)
  const rEnc = (r[0]! & 0x80) === 0 ? r : Buffer.concat([Buffer.from([0]), r])
  const sEnc = (s[0]! & 0x80) === 0 ? s : Buffer.concat([Buffer.from([0]), s])
  return Buffer.concat([
    Buffer.from([0x30, rEnc.length + sEnc.length + 4]),
    Buffer.from([0x02, rEnc.length]),
    rEnc,
    Buffer.from([0x02, sEnc.length]),
    sEnc,
  ])
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  issue(sid: string, session: Session.ISession, _opts: Transport.IssueOpts): Provider.Intent[] {
    const now = Math.floor(Date.now() / 1000)
    const exp = Math.min(now + Math.floor(this._ttlMs / 1000), Math.floor(session.expiresAt / 1000))
    const signAlg: JwtAlg = this._cfg.signKey.alg ?? 'HS256'
    const headerObj: { alg: JwtAlg; typ: 'JWT'; kid: string } = {
      alg: signAlg,
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
      knd: session.kind,
      ...(this._cfg.audience !== undefined && { aud: this._cfg.audience }),
      ...(session.tenantId !== undefined && { tid: session.tenantId }),
      ...(session.actingAs !== undefined && { acting_as: session.actingAs }),
    }
    const headerB64 = base64urlEncode(JSON.stringify(headerObj))
    const payloadB64 = base64urlEncode(JSON.stringify(payload))
    const signingInput = `${headerB64}.${payloadB64}`
    const sig = jwsSign(signAlg, this._cfg.signKey.key, signingInput)
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
    if (header.typ !== 'JWT' || !header.kid) return null
    if (header.alg !== 'HS256' && header.alg !== 'ES256' && header.alg !== 'RS256') return null

    const key = this._verifyKeys.get(header.kid)
    if (!key) return null
    // Pin the alg to the key configuration to prevent alg-confusion
    // attacks (RFC 8725 section 3.1).
    const expectedAlg: JwtAlg = key.alg ?? 'HS256'
    if (header.alg !== expectedAlg) return null
    if (key.notAfter !== undefined && key.notAfter < Date.now()) return null

    if (!jwsVerify(expectedAlg, key.key, `${headerB64}.${payloadB64}`, sig)) return null

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
      kind: payload.knd ?? (payload.sub ? 'user' : 'guest'),
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
   * Emit a JWKS document for the asymmetric verify keys. HS256 keys
   * are skipped (symmetric secrets must never appear in JWKS). RS256
   * + ES256 PEM keys are parsed via `createPublicKey` and exported as
   * JWK with the configured `kid` + `alg` + `use:'sig'`.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  jwks(): { keys: Array<Record<string, unknown>> } {
    const out: Array<Record<string, unknown>> = []
    for (const key of this._verifyKeys.values()) {
      const alg: JwtAlg = key.alg ?? 'HS256'
      if (alg === 'HS256') continue
      try {
        const pub = createPublicKey(key.key).export({ format: 'jwk' }) as Record<string, unknown>
        out.push({ ...pub, kid: key.kid, alg, use: 'sig' })
      } catch {
        // Skip malformed key rather than fail the whole document.
      }
    }
    return { keys: out }
  }

  /**
   * Mint a fresh JWT from a session without rotating the SID. Used by
   * refresh endpoints after verifying the refresh cookie.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  static mintFresh(transport: JwtTransport, sid: string, session: Session.ISession): Provider.Intent[] {
    return transport.issue(sid, session, { fresh: true, absolute: false })
  }
}

// Re-export for parity with cookie/bearer transports.
export { randomToken, sha256 }

/**
 * Namespace merge for JwtTransport. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging. Consumers can
 * write either the flat name (e.g. JwtTransportConfig) or the
 * namespaced form (JwtTransport.IConfig); both
 * resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace JwtTransport {
  /** Alias for the flat `JwtTransportConfig` type. */
  export type IConfig = JwtTransportConfig
  /** Alias for the flat `JwtVerifyKey` type. */
  export type IVerifyKey = JwtVerifyKey
  /** Alias for the flat `JwtAlg` type. */
  export type IJwtAlg = JwtAlg
}
