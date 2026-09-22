import { createPublicKey } from 'node:crypto'
import { type Answer, answer } from '../answer'
import { randomToken, sha256 } from '../crypto'
import { AuthError } from '../errors'
import { isExpiredAt } from '../predicates/predicates'
import type { Provider } from '../provider/provider.types'
import { AUTH_SESSION_FACTOR_METHODS, type Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'
import { signEddsa, verifyEddsa } from './jwt-algs/eddsa.alg'
import { signEs256, verifyEs256 } from './jwt-algs/es256.alg'
import { signHs256, verifyHs256 } from './jwt-algs/hs256.alg'
import { signRs256, verifyRs256 } from './jwt-algs/rs256.alg'

/**
 * Stateless, for edge and serverless, over `node:crypto`. HS256, ES256, RS256 and EdDSA, with the alg
 * pinned per kid to defeat alg-confusion (RFC 8725 section 3.1). Refresh tokens are opaque cookies
 * rotated server-side.
 */

const DEFAULT_REFRESH_COOKIE = '__Host-duck-refresh'

export namespace JwtTransport {
  export interface Cfg {
    /** `key` is the secret for HS256 and the PEM-encoded private key for ES256 and RS256. `alg` defaults
     *  to HS256. */
    signKey: { kid: string; alg?: JwtTransport.IJwtAlg; key: string }
    /** Every currently-valid verify key, `signKey` included. During rotation the previous keys stay
     *  for an overlap window, so already-issued tokens keep verifying. */
    verifyKeys: JwtTransport.IVerifyKey[]
    issuer: string
    audience?: string
    /** JWT TTL in ms. Default 15 minutes. */
    ttlMs?: number
    /** Freshness window in ms: a round trip reconstructs the session with
     *  `fresh = (now - rotatedAt) < freshnessMs`. Default 5 minutes, matching `Sessions.Cfg`.
     *  WARN: privileged operations branch on `fresh`, so too high a value disables the gate. */
    freshnessMs?: number
    /** Optional refresh cookie shape. */
    refresh?: {
      /** Cookie name carrying the opaque refresh token. */
      cookieName?: string
      /** Refresh TTL in ms. Default 7 days. */
      ttlMs?: number
    }
  }

  export interface IVerifyKey {
    kid: string
    /** `'HS256'` by default, for backwards compatibility; ES256 and RS256 callers set it explicitly. */
    alg?: JwtTransport.IJwtAlg
    /** The UTF-8 secret for `HS256`, and the PEM-encoded public key (SPKI or RSA-PUBLIC) for `ES256`
     *  and `RS256`. */
    key: string
    /** Rotation cutoff: verify-only past this point. */
    notAfter?: number
  }

  export type IJwtAlg = 'HS256' | 'ES256' | 'RS256' | 'EdDSA'

  export interface IRotateOpts {
    /** Effective for every subsequent `issue()`. */
    signKey: { kid: string; alg?: IJwtAlg; key: string }
    /** The verify-side entry for the new key. Required for asymmetric algs, where `signKey` carries
     *  the private key and the ring needs its public counterpart. */
    verifyKey?: IVerifyKey
  }

  export interface Payload {
    /** Issuer. */
    iss: string
    /** Subject: the identity id. */
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
    aal: Sessions.AAL
    /** Method names only; the parser checks each against {@link Sessions.FactorMethod}. */
    factors: Sessions.FactorMethod[]
    /** Tenant id when present. */
    tid?: string
    /** Acting-as envelope when impersonating. Timestamps are epoch seconds on the wire. */
    acting_as?: { realIdentityId: string; startedAt: number; reason: string; expiresAt: number }
    /** `'user' | 'apikey' | 'guest'`, preserved so an M2M token round-trips. */
    knd?: Sessions.Kind
    /** Epoch seconds, driving `session.fresh = now - rotatedAt < freshnessMs`. */
    frsh?: number
    /** Space-separated OAuth scope, emitted when `issue()` was given one, so a resource server
     *  branches without an out-of-band lookup. What gives `M2MImpl`'s `scopeMode` wire-level effect. */
    scope?: string
  }
}

function base64urlEncode(s: string | Buffer): string {
  return (typeof s === 'string' ? Buffer.from(s) : s).toString('base64url')
}

function base64urlDecode(s: string): string {
  return Buffer.from(s, 'base64url').toString('utf8')
}

function jwsSign(alg: JwtTransport.IJwtAlg, key: string, signingInput: string): string {
  switch (alg) {
    case 'HS256':
      return signHs256(key, signingInput)
    case 'RS256':
      return signRs256(key, signingInput)
    case 'EdDSA':
      return signEddsa(key, signingInput)
    case 'ES256':
      return signEs256(key, signingInput)
  }
}

function jwsVerify(alg: JwtTransport.IJwtAlg, key: string, signingInput: string, sigB64: string): boolean {
  switch (alg) {
    case 'HS256':
      return verifyHs256(key, signingInput, sigB64)
    case 'RS256':
      return verifyRs256(key, signingInput, sigB64)
    case 'EdDSA':
      return verifyEddsa(key, signingInput, sigB64)
    case 'ES256':
      return verifyEs256(key, signingInput, sigB64)
  }
}

/** Runtime validators for JWT header + payload; any rejection makes `verify()` return `null`. */
// Derived, not restated: a method added to the constant but not to a second copy here would be
// dropped from every parsed token while the source of truth still called it valid.
const FACTOR_METHOD_VALUES: ReadonlySet<string> = new Set<Sessions.FactorMethod>(AUTH_SESSION_FACTOR_METHODS)
const SESSION_KIND_VALUES: ReadonlySet<string> = new Set<Sessions.Kind>(['guest', 'user', 'apikey'])
const JWT_ALG_VALUES: ReadonlySet<string> = new Set<JwtTransport.IJwtAlg>(['HS256', 'ES256', 'RS256', 'EdDSA'])

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isFactorMethod(v: unknown): v is Sessions.FactorMethod {
  return typeof v === 'string' && FACTOR_METHOD_VALUES.has(v)
}

function isSessionKind(v: unknown): v is Sessions.Kind {
  return typeof v === 'string' && SESSION_KIND_VALUES.has(v)
}

type JwtActingAs = NonNullable<JwtTransport.Payload['acting_as']>

function isActingAs(v: unknown): v is JwtActingAs {
  if (!isPlainObject(v)) return false
  return (
    typeof v.realIdentityId === 'string' &&
    typeof v.startedAt === 'number' &&
    Number.isFinite(v.startedAt) &&
    typeof v.reason === 'string' &&
    typeof v.expiresAt === 'number' &&
    Number.isFinite(v.expiresAt)
  )
}

function isJwtAlg(v: unknown): v is JwtTransport.IJwtAlg {
  return typeof v === 'string' && JWT_ALG_VALUES.has(v)
}

interface JwtHeaderShape {
  alg: JwtTransport.IJwtAlg
  kid: string
  typ: 'JWT'
}

function parseJwtHeader(raw: unknown): JwtHeaderShape | null {
  if (!isPlainObject(raw)) return null
  const { alg, kid, typ } = raw
  if (typ !== 'JWT') return null
  if (typeof kid !== 'string' || kid.length === 0) return null
  if (!isJwtAlg(alg)) return null
  return { alg, kid, typ }
}

function parseJwtPayload(raw: unknown): JwtTransport.Payload | null {
  if (!isPlainObject(raw)) return null
  const { iss, sub, aud, iat, exp, sid, aal, factors, tid, acting_as, knd, frsh, scope } = raw
  if (typeof iss !== 'string') return null
  if (sub !== null && typeof sub !== 'string') return null
  if (aud !== undefined && typeof aud !== 'string') return null
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return null
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return null
  if (typeof sid !== 'string') return null
  if (aal !== 1 && aal !== 2 && aal !== 3) return null
  if (!Array.isArray(factors)) return null
  if (factors.length > 16) return null
  const narrowedFactors: Sessions.FactorMethod[] = []
  for (const f of factors) {
    if (!isFactorMethod(f)) return null
    narrowedFactors.push(f)
  }
  if (tid !== undefined && typeof tid !== 'string') return null
  if (acting_as !== undefined && !isActingAs(acting_as)) return null
  if (knd !== undefined && !isSessionKind(knd)) return null
  if (frsh !== undefined && (typeof frsh !== 'number' || !Number.isFinite(frsh))) return null
  if (scope !== undefined && typeof scope !== 'string') return null
  const payload: JwtTransport.Payload = { iss, sub, iat, exp, sid, aal, factors: narrowedFactors }
  if (aud !== undefined) payload.aud = aud
  if (tid !== undefined) payload.tid = tid
  if (acting_as !== undefined) payload.acting_as = acting_as
  if (knd !== undefined) payload.knd = knd
  if (frsh !== undefined) payload.frsh = frsh
  if (scope !== undefined) payload.scope = scope
  return payload
}

/** Stateless JWT transport: signs the session into the token and verifies it without a store read. */
export class JwtTransport implements Transport.ITransport {
  private readonly _verifyKeys: Map<string, JwtTransport.IVerifyKey>
  private _signKey: JwtTransport.Cfg['signKey']
  private readonly _ttlMs: number
  private readonly _freshnessMs: number
  private readonly _refreshCookieName: string
  private readonly _refreshTtlMs: number
  private readonly _refreshEnabled: boolean
  /** Read by `strict()`, which enforces the production floor. A boolean, never the key. */
  readonly __weakSigningKey: boolean

  constructor(private readonly _cfg: JwtTransport.Cfg) {
    // The kid flows into the JOSE header of every token, so a huge or non-string one inflates them all.
    if (typeof _cfg.signKey.kid !== 'string' || _cfg.signKey.kid.length === 0 || _cfg.signKey.kid.length > 256) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthJwtTransport.signKey.kid must be a non-empty string <=256 chars',
      })
    }
    if (typeof _cfg.signKey.key !== 'string' || _cfg.signKey.key.length === 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthJwtTransport.signKey.key must be a non-empty string (HS256 secret or PEM)',
      })
    }
    // RFC 7518 section 3.2 puts a floor under the HMAC algorithms; an asymmetric `key` is a PEM, whose
    // strength is in the key it encodes and not in its length. Recorded, not thrown: a short secret is a
    // production footgun, and `strict({ env: 'production' })` is where those are refused.
    this.__weakSigningKey =
      (_cfg.signKey.alg ?? 'HS256').startsWith('HS') && Buffer.byteLength(_cfg.signKey.key, 'utf8') < 32
    // No duplicate kid: the Map constructor takes the last silently, leaving an operator with two kids
    // in config and one effective entry. Surfaced at boot instead.
    const seen = new Set<string>()
    for (const k of _cfg.verifyKeys) {
      if (typeof k.kid !== 'string' || k.kid.length === 0 || k.kid.length > 256) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'AuthJwtTransport.verifyKeys[*].kid must be a non-empty string <=256 chars',
        })
      }
      if (seen.has(k.kid)) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `AuthJwtTransport.verifyKeys has duplicate kid '${k.kid}'`,
        })
      }
      seen.add(k.kid)
    }
    this._verifyKeys = new Map(_cfg.verifyKeys.map((k) => [k.kid, k]))
    // A signKey kid that also appears in verifyKeys must match on alg, and on key material for HS*:
    // otherwise a typo silently swaps signing material under a shared kid label.
    const matchedVerify = this._verifyKeys.get(_cfg.signKey.kid)
    if (matchedVerify) {
      const signAlg = _cfg.signKey.alg ?? 'HS256'
      const verifyAlg = matchedVerify.alg ?? 'HS256'
      if (signAlg !== verifyAlg) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `AuthJwtTransport.signKey '${_cfg.signKey.kid}' alg (${signAlg}) does not match the verifyKeys entry alg (${verifyAlg})`,
        })
      }
      if (signAlg === 'HS256' && matchedVerify.key !== _cfg.signKey.key) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `AuthJwtTransport.signKey '${_cfg.signKey.kid}' (HS256) does not match the verifyKeys entry under the same kid`,
        })
      }
    } else {
      this._verifyKeys.set(_cfg.signKey.kid, {
        kid: _cfg.signKey.kid,
        key: _cfg.signKey.key,
        ...(_cfg.signKey.alg !== undefined && { alg: _cfg.signKey.alg }),
      })
    }
    this._signKey = _cfg.signKey
    this._ttlMs = _cfg.ttlMs ?? 15 * 60 * 1000
    this._freshnessMs = _cfg.freshnessMs ?? 5 * 60 * 1000
    this._refreshEnabled = Boolean(_cfg.refresh)
    this._refreshCookieName = _cfg.refresh?.cookieName ?? DEFAULT_REFRESH_COOKIE
    this._refreshTtlMs = _cfg.refresh?.ttlMs ?? 7 * 24 * 60 * 60 * 1000
  }

  /** Header form preferred, with the cookie as the refresh fallback. */
  extract(req: { headers: Headers }): string | null {
    const auth = req.headers.get('authorization')
    if (!auth) return null
    // Case-insensitive scheme match (RFC 7235), a 4KB cap, and comma-joined multi-Authorization
    // smuggling refused.
    const head = auth.slice(0, 'Bearer '.length).toLowerCase()
    if (head !== 'bearer ') return null
    const token = auth.slice('Bearer '.length).trim()
    if (!token) return null
    if (token.length > 4096) return null
    if (token.includes(',')) return null
    return token
  }

  /** Issue an access JWT and, with refresh enabled, an opaque refresh cookie carrying the plaintext
   *  SID, which is what the framework adapter reads back at refresh time. */
  issue(sid: string, session: Sessions.Me, opts: Transport.IssueOpts): Provider.Intent[] {
    const now = Math.floor(Date.now() / 1000)
    const sessionExpiresMs =
      session.expiresAt instanceof Date ? session.expiresAt.getTime() : (session.expiresAt as number)
    const exp = Math.min(now + Math.floor(this._ttlMs / 1000), Math.floor(sessionExpiresMs / 1000))
    const signAlg: JwtTransport.IJwtAlg = this._signKey.alg ?? 'HS256'
    const headerObj: { alg: JwtTransport.IJwtAlg; typ: 'JWT'; kid: string } = {
      alg: signAlg,
      typ: 'JWT',
      kid: this._signKey.kid,
    }
    const payload: JwtTransport.Payload = {
      iss: this._cfg.issuer,
      sub: session.identityId,
      iat: now,
      exp,
      sid: session.id,
      aal: session.aal,
      factors: session.factors.map((f) => f.method),
      knd: session.kind,
      // rotatedAt in epoch seconds, so `verify()` computes `fresh` without a store hit: a cookie session
      // reads it off the row, and a JWT has to carry it on the wire.
      frsh: Math.floor(
        (session.rotatedAt instanceof Date ? session.rotatedAt.getTime() : (session.rotatedAt as number)) / 1000,
      ),
      ...(this._cfg.audience !== undefined && { aud: this._cfg.audience }),
      ...(session.tenantId != null && { tid: session.tenantId }),
      ...(session.actingAs != null && {
        acting_as: {
          ...session.actingAs,
          startedAt: Math.floor(
            (session.actingAs.startedAt instanceof Date
              ? session.actingAs.startedAt.getTime()
              : (session.actingAs.startedAt as number)) / 1000,
          ),
          expiresAt: Math.floor(
            (session.actingAs.expiresAt instanceof Date
              ? session.actingAs.expiresAt.getTime()
              : (session.actingAs.expiresAt as number)) / 1000,
          ),
        },
      }),
      ...(opts.scope !== undefined && { scope: opts.scope }),
    }
    const headerB64 = base64urlEncode(JSON.stringify(headerObj))
    const payloadB64 = base64urlEncode(JSON.stringify(payload))
    const signingInput = `${headerB64}.${payloadB64}`
    const sig = jwsSign(signAlg, this._signKey.key, signingInput)
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

  /** Revokes the refresh cookie when one is in use; a no-op for the stateless JWT. */
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

  /** Reconstructs the session with no store hit. */
  verify(token: string): Answer.Me<Sessions.Me> {
    return answer(async () => {
      if (typeof token !== 'string' || token.length === 0 || token.length > 4096) {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'token is empty or over the 4096-character cap' })
      }
      const [headerB64, payloadB64, sig, ...rest] = token.split('.')
      if (rest.length > 0 || headerB64 === undefined || payloadB64 === undefined || sig === undefined) {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'token is not a three-part JWS' })
      }

      let rawHeader: unknown
      try {
        rawHeader = JSON.parse(base64urlDecode(headerB64))
      } catch {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the header is not decodable base64url JSON' })
      }
      const header = parseJwtHeader(rawHeader)
      if (!header)
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the header is missing or has a malformed alg or kid' })

      const key = this._verifyKeys.get(header.kid)
      if (!key)
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'no verification key is configured for this kid' })
      // Pinned to the key configuration, against alg-confusion (RFC 8725 section 3.1).
      const expectedAlg: JwtTransport.IJwtAlg = key.alg ?? 'HS256'
      if (header.alg !== expectedAlg)
        throw new AuthError('AUTH_SESSION_REVOKED', {
          reason: 'the header alg does not match the alg pinned to the key',
        })
      // `isExpiredAt` fail-closes; non-finite `notAfter` would slip past expiry.
      if (isExpiredAt(key.notAfter))
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the verification key is past its notAfter' })

      if (!jwsVerify(expectedAlg, key.key, `${headerB64}.${payloadB64}`, sig))
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the signature does not verify under that key' })

      let rawPayload: unknown
      try {
        rawPayload = JSON.parse(base64urlDecode(payloadB64))
      } catch {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the payload is not decodable base64url JSON' })
      }
      const payload = parseJwtPayload(rawPayload)
      if (!payload)
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the payload is missing or has a malformed claim' })

      const nowSec = Math.floor(Date.now() / 1000)
      if (payload.exp < nowSec) throw new AuthError('AUTH_SESSION_EXPIRED', { expiredAt: payload.exp * 1000 })
      if (payload.iss !== this._cfg.issuer)
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'iss does not match the configured issuer' })
      if (this._cfg.audience !== undefined && payload.aud !== this._cfg.audience)
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'aud does not match the configured audience' })

      // `frsh` claim (or `iat` fallback) matches cookie-session freshness window.
      const rotatedAtMs = (payload.frsh ?? payload.iat) * 1000
      const completedAtDate = new Date(payload.iat * 1000)
      const session: Sessions.Me = {
        id: payload.sid,
        identityId: payload.sub,
        tenantId: payload.tid ?? null,
        kind: payload.knd ?? (payload.sub ? 'user' : 'guest'),
        aal: payload.aal,
        factors: payload.factors.map((m) => ({ method: m, completedAt: completedAtDate })),
        csrfHash: null,
        ip: null,
        userAgent: null,
        fingerprint: null,
        createdAt: new Date(payload.iat * 1000),
        // No stored row to have been updated: the claims were last written when the token was minted.
        updatedAt: new Date(payload.iat * 1000),
        rotatedAt: new Date(rotatedAtMs),
        expiresAt: new Date(payload.exp * 1000),
        absoluteExpiresAt: new Date(payload.exp * 1000),
        // SECURITY: bounds both ends. `frsh` is minted on the issuing clock and read on the verifying one,
        // so a bare `now - frsh` makes a future stamp permanently fresh and the step-up gate permanently met.
        fresh: Math.abs(Date.now() - rotatedAtMs) < this._freshnessMs,
        actingAs: null,
      }
      if (payload.acting_as !== undefined) {
        const aa = payload.acting_as
        session.actingAs = {
          realIdentityId: aa.realIdentityId,
          reason: aa.reason,
          startedAt: new Date(aa.startedAt * 1000),
          expiresAt: new Date(aa.expiresAt * 1000),
        }
      }
      // Stateless JWT mode enforces actingAs expiry at verify time.
      if (session.actingAs?.expiresAt !== undefined && isExpiredAt(session.actingAs.expiresAt)) {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the impersonation window has closed' })
      }
      return session
    })
  }

  /** A JWKS document for the asymmetric verify keys, exported with their `kid`, `alg` and `use: 'sig'`.
   *  SECURITY: HS256 keys are skipped, since a symmetric secret must never appear in a JWKS. */
  jwks(): { keys: Array<Record<string, unknown>> } {
    const out: Array<Record<string, unknown>> = []
    for (const key of this._verifyKeys.values()) {
      const alg: JwtTransport.IJwtAlg = key.alg ?? 'HS256'
      if (alg === 'HS256') continue
      try {
        const pub = createPublicKey(key.key).export({ format: 'jwk' }) as Record<string, unknown>
        out.push({ ...pub, kid: key.kid, alg, use: 'sig' })
      } catch {
        // A malformed key is skipped rather than failing the whole document.
      }
    }
    return { keys: out }
  }

  /** Mints a fresh JWT from a session without rotating the SID, for a refresh endpoint that has already
   *  verified the refresh cookie. */
  static mintFresh(transport: JwtTransport, sid: string, session: Sessions.Me): Provider.Intent[] {
    return transport.issue(sid, session, { fresh: true, absolute: false })
  }

  /** Promote a new signing key and add its public counterpart to the verify ring atomically. Older
   *  keys stay under their original kid so issued tokens keep verifying, until `retireVerifyKey`. */
  rotateSignKey(opts: JwtTransport.IRotateOpts): void {
    const newSign = opts.signKey
    const newAlg: JwtTransport.IJwtAlg = newSign.alg ?? 'HS256'
    // Omitting `verifyKey` is fine only when this kid is already in the ring under a matching alg;
    // otherwise no verifier holds its public key and every token minted under the rotation fails.
    if (newAlg !== 'HS256' && !opts.verifyKey) {
      const known = this._verifyKeys.get(newSign.kid)
      if (!known || (known.alg ?? 'HS256') !== newAlg) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `rotateSignKey: ${newAlg} requires a public verifyKey`,
        })
      }
    }
    if (opts.verifyKey && opts.verifyKey.kid !== newSign.kid) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'rotateSignKey: verifyKey.kid must match signKey.kid',
      })
    }
    if (opts.verifyKey) {
      const existing = this._verifyKeys.get(opts.verifyKey.kid)
      if (existing && (existing.alg ?? 'HS256') !== (opts.verifyKey.alg ?? 'HS256')) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `rotateSignKey: verifyKey '${opts.verifyKey.kid}' alg conflicts with existing entry`,
        })
      }
      this._verifyKeys.set(opts.verifyKey.kid, opts.verifyKey)
    } else if (newAlg === 'HS256') {
      // HS256 is symmetric, so the verify side must hold the same secret.
      this._verifyKeys.set(newSign.kid, {
        kid: newSign.kid,
        key: newSign.key,
        ...(newSign.alg !== undefined && { alg: newSign.alg }),
      })
    }
    this._signKey = newSign
  }

  /** Remove a kid from the verify ring once its grace window has passed. Refuses the current signing
   *  kid. */
  retireVerifyKey(kid: string): void {
    if (kid === this._signKey.kid) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `retireVerifyKey: refusing to remove the active signing kid '${kid}'`,
      })
    }
    this._verifyKeys.delete(kid)
  }
}

/** Constructs a {@link JwtTransport}. */
export function jwtTransport(cfg: JwtTransport.Cfg): JwtTransport {
  return new JwtTransport(cfg)
}

// Re-export for parity with cookie/bearer transports.
export { randomToken as authRandomToken, sha256 as authSha256 }
