import { createPublicKey } from 'node:crypto'
import { isExpiredAt } from '../credential-utils'
import { randomToken, sha256 } from '../crypto'
import { AuthErrorObject } from '../errors'
import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'
import { signEddsa, verifyEddsa } from './jwt-algs/eddsa'
import { signEs256, verifyEs256 } from './jwt-algs/es256'
import { signHs256, verifyHs256 } from './jwt-algs/hs256'
import { signRs256, verifyRs256 } from './jwt-algs/rs256'

/**
 * JwtTransport - stateless transport for edge / serverless deployments.
 * Verifies tokens locally so resolveSession() avoids a store hit on the
 * hot path. Algorithms: HS256 (HMAC), ES256 (P-256), RS256 (RSA),
 * EdDSA (Ed25519) - all via `node:crypto`, no `jose` dependency.
 *
 * Token shape: standard JWT `<header>.<payload>.<sig>` base64url-encoded.
 * Header is `{ alg, typ: 'JWT', kid }` with `alg` pinned per-kid to
 * defeat alg-confusion (RFC 8725 §3.1).
 *
 * Live JWKS rotation: `rotateSignKey()` promotes a new signing key;
 * `retireVerifyKey(kid)` removes a retired key after its overlap window.
 *
 * Refresh tokens are issued as opaque cookies (the persisted half of the
 * dual transport) and rotated server-side. Reuse detection at refresh
 * time follows the same family-id mechanism as OAuth refresh tokens.
 */

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
  /** Session factors (method names only). Parser validates each entry against {@link Session.FactorMethod}. */
  factors: Session.FactorMethod[]
  /** Tenant id when present. */
  tid?: string
  /** Acting-as envelope when impersonating. */
  acting_as?: Session.ActingAs
  /** Session kind (`'user' | 'apikey' | 'guest'`). Preserved so M2M tokens round-trip correctly. */
  knd?: Session.Kind
  /**
   * Session rotation timestamp, seconds since epoch. Used by `verify()`
   * to compute `session.fresh = now - rotatedAt < freshnessMs`. Without
   * this claim, `verify()` would have to assume `fresh: true` for every
   * still-valid JWT, defeating the AAL-2 freshness gate that protects
   * privileged operations like password reset with TOTP.
   */
  frsh?: number
  /**
   * OAuth-style scope string (space-separated). Emitted when
   * `issue()` was called with `Transport.IssueOpts.scope`. Resource
   * servers branch on this without an out-of-band scope lookup. Used
   * by the M2MFacet client_credentials grant so the `scopeMode` knob
   * has wire-level effect.
   */
  scope?: string
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

/**
 * validators for the JWT header + payload. JSON-parsed claims are
 * attacker-controlled bytes; declaring them as a typed shape via `let
 * x: Shape = JSON.parse(...)` is a TS-only assertion that does NOT
 * validate at runtime. Previously this allowed:
 *
 *  - a missing/non-numeric `exp` to silently bypass expiry
 *    (`undefined < nowSec` is `NaN < N === false`),
 *  - a non-array `factors` to crash `verify()` with `TypeError: .map`,
 *  - a non-string entry in `factors` to slip through `as FactorMethod`
 *    and land in the reconstructed session,
 *  - a non-1/2/3 `aal` value to land in the session and skew AAL gates.
 *
 * The parsers below accept only well-formed JWTs; any rejection makes
 * `verify()` return `null` (matching the pre-existing failure contract).
 */
const FACTOR_METHOD_VALUES: ReadonlySet<string> = new Set<Session.FactorMethod>([
  'password',
  'passkey',
  'totp',
  'oauth',
  'magic-link',
  'webauthn',
  'sms',
  'api-key',
  'backup-code',
])
const SESSION_KIND_VALUES: ReadonlySet<string> = new Set<Session.Kind>(['guest', 'user', 'apikey'])
const JWT_ALG_VALUES: ReadonlySet<string> = new Set<JwtTransport.IJwtAlg>(['HS256', 'ES256', 'RS256', 'EdDSA'])

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isFactorMethod(v: unknown): v is Session.FactorMethod {
  return typeof v === 'string' && FACTOR_METHOD_VALUES.has(v)
}

function isSessionKind(v: unknown): v is Session.Kind {
  return typeof v === 'string' && SESSION_KIND_VALUES.has(v)
}

function isActingAs(v: unknown): v is Session.ActingAs {
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

function parseJwtPayload(raw: unknown): JwtPayload | null {
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
  const narrowedFactors: Session.FactorMethod[] = []
  for (const f of factors) {
    if (!isFactorMethod(f)) return null
    narrowedFactors.push(f)
  }
  if (tid !== undefined && typeof tid !== 'string') return null
  if (acting_as !== undefined && !isActingAs(acting_as)) return null
  if (knd !== undefined && !isSessionKind(knd)) return null
  if (frsh !== undefined && (typeof frsh !== 'number' || !Number.isFinite(frsh))) return null
  if (scope !== undefined && typeof scope !== 'string') return null
  const payload: JwtPayload = { iss, sub, iat, exp, sid, aal, factors: narrowedFactors }
  if (aud !== undefined) payload.aud = aud
  if (tid !== undefined) payload.tid = tid
  if (acting_as !== undefined) payload.acting_as = acting_as
  if (knd !== undefined) payload.knd = knd
  if (frsh !== undefined) payload.frsh = frsh
  if (scope !== undefined) payload.scope = scope
  return payload
}

export class JwtTransport implements Transport.ITransport {
  private readonly _verifyKeys: Map<string, JwtTransport.IVerifyKey>
  private _signKey: JwtTransport.IConfig['signKey']
  private readonly _ttlMs: number
  private readonly _freshnessMs: number
  private readonly _refreshCookieName: string
  private readonly _refreshTtlMs: number
  private readonly _refreshEnabled: boolean

  constructor(private readonly _cfg: JwtTransport.IConfig) {
    // signKey kid sanity check; flows into the JOSE header per token. A
    // huge or non-string kid would inflate every issued JWT.
    if (typeof _cfg.signKey.kid !== 'string' || _cfg.signKey.kid.length === 0 || _cfg.signKey.kid.length > 256) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'JwtTransport.signKey.kid must be a non-empty string <=256 chars',
      })
    }
    if (typeof _cfg.signKey.key !== 'string' || _cfg.signKey.key.length === 0) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'JwtTransport.signKey.key must be a non-empty string (HS256 secret or PEM)',
      })
    }
    // assert verifyKeys carries no duplicate kid. The Map constructor
    // would silently last-wins, leaving operators with two kids in config
    // but one effective entry. Surface the misconfig at boot.
    const seen = new Set<string>()
    for (const k of _cfg.verifyKeys) {
      if (typeof k.kid !== 'string' || k.kid.length === 0 || k.kid.length > 256) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: 'JwtTransport.verifyKeys[*].kid must be a non-empty string <=256 chars',
        })
      }
      if (seen.has(k.kid)) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: `JwtTransport.verifyKeys has duplicate kid '${k.kid}'`,
        })
      }
      seen.add(k.kid)
    }
    this._verifyKeys = new Map(_cfg.verifyKeys.map((k) => [k.kid, k]))
    // If the signKey's kid is also in verifyKeys, alg + key material
    // (for HS*) must match; catches operator typos that would silently
    // swap signing material under a shared kid label.
    const matchedVerify = this._verifyKeys.get(_cfg.signKey.kid)
    if (matchedVerify) {
      const signAlg = _cfg.signKey.alg ?? 'HS256'
      const verifyAlg = matchedVerify.alg ?? 'HS256'
      if (signAlg !== verifyAlg) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: `JwtTransport.signKey '${_cfg.signKey.kid}' alg (${signAlg}) does not match the verifyKeys entry alg (${verifyAlg})`,
        })
      }
      if (signAlg === 'HS256' && matchedVerify.key !== _cfg.signKey.key) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: `JwtTransport.signKey '${_cfg.signKey.kid}' (HS256) does not match the verifyKeys entry under the same kid`,
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

  /** Pull the Bearer access token (header form preferred; cookie fallback for refresh). */
  extract(req: { headers: Headers }): string | null {
    const auth = req.headers.get('authorization')
    if (!auth) return null
    // Case-insensitive scheme match (RFC 7235), 4KB cap, reject
    // comma-joined multi-Authorization smuggling.
    const head = auth.slice(0, 'Bearer '.length).toLowerCase()
    if (head !== 'bearer ') return null
    const token = auth.slice('Bearer '.length).trim()
    if (!token) return null
    if (token.length > 4096) return null
    if (token.includes(',')) return null
    return token
  }

  /**
   * Issue an access JWT plus (when refresh enabled) an opaque refresh
   * cookie. The plaintext SID is used as the refresh cookie value so
   * the framework adapter can read it back at refresh time.
   */
  issue(sid: string, session: Session.ISession, opts: Transport.IssueOpts): Provider.Intent[] {
    const now = Math.floor(Date.now() / 1000)
    const exp = Math.min(now + Math.floor(this._ttlMs / 1000), Math.floor(session.expiresAt / 1000))
    const signAlg: JwtTransport.IJwtAlg = this._signKey.alg ?? 'HS256'
    const headerObj: { alg: JwtTransport.IJwtAlg; typ: 'JWT'; kid: string } = {
      alg: signAlg,
      typ: 'JWT',
      kid: this._signKey.kid,
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
      // rotatedAt-epoch seconds. Lets `verify()` compute `fresh` without
      // a store hit (cookie sessions get this from the store row; JWTs
      // must carry it on the wire).
      frsh: Math.floor(session.rotatedAt / 1000),
      ...(this._cfg.audience !== undefined && { aud: this._cfg.audience }),
      ...(session.tenantId !== undefined && { tid: session.tenantId }),
      ...(session.actingAs !== undefined && { acting_as: session.actingAs }),
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
    if (typeof token !== 'string' || token.length === 0 || token.length > 4096) {
      return null
    }
    const [headerB64, payloadB64, sig, ...rest] = token.split('.')
    if (rest.length > 0 || headerB64 === undefined || payloadB64 === undefined || sig === undefined) {
      return null
    }

    let rawHeader: unknown
    try {
      rawHeader = JSON.parse(base64urlDecode(headerB64))
    } catch {
      return null
    }
    const header = parseJwtHeader(rawHeader)
    if (!header) return null

    const key = this._verifyKeys.get(header.kid)
    if (!key) return null
    // Pin the alg to the key configuration to prevent alg-confusion
    // attacks (RFC 8725 section 3.1).
    const expectedAlg: JwtTransport.IJwtAlg = key.alg ?? 'HS256'
    if (header.alg !== expectedAlg) return null
    // `isExpiredAt` fail-closes; non-finite `notAfter` would slip past expiry.
    if (isExpiredAt(key.notAfter)) return null

    if (!jwsVerify(expectedAlg, key.key, `${headerB64}.${payloadB64}`, sig)) return null

    let rawPayload: unknown
    try {
      rawPayload = JSON.parse(base64urlDecode(payloadB64))
    } catch {
      return null
    }
    // parser rejects missing/non-numeric exp, non-array factors,
    // non-string factor entries, and non-1/2/3 aal - each of which
    // previously either bypassed a check or crashed `verify()`.
    const payload = parseJwtPayload(rawPayload)
    if (!payload) return null

    const nowSec = Math.floor(Date.now() / 1000)
    if (payload.exp < nowSec) return null
    if (payload.iss !== this._cfg.issuer) return null
    if (this._cfg.audience !== undefined && payload.aud !== this._cfg.audience) return null

    // `frsh` claim (or `iat` fallback) matches cookie-session freshness window.
    const rotatedAtMs = (payload.frsh ?? payload.iat) * 1000
    const session: Session.ISession = {
      id: payload.sid,
      identityId: payload.sub,
      kind: payload.knd ?? (payload.sub ? 'user' : 'guest'),
      aal: payload.aal,
      factors: payload.factors.map((m) => ({ method: m, completedAt: payload.iat * 1000 })),
      createdAt: payload.iat * 1000,
      rotatedAt: rotatedAtMs,
      expiresAt: payload.exp * 1000,
      absoluteExpiresAt: payload.exp * 1000,
      fresh: Date.now() - rotatedAtMs < this._freshnessMs,
    }
    if (payload.tid !== undefined) session.tenantId = payload.tid
    if (payload.acting_as !== undefined) session.actingAs = payload.acting_as
    // Stateless JWT mode enforces actingAs expiry at verify time.
    if (session.actingAs?.expiresAt !== undefined && isExpiredAt(session.actingAs.expiresAt)) {
      return null
    }
    return session
  }

  /**
   * Emit a JWKS document for the asymmetric verify keys. HS256 keys
   * are skipped (symmetric secrets must never appear in JWKS). RS256
   * + ES256 PEM keys are parsed via `createPublicKey` and exported as
   * JWK with the configured `kid` + `alg` + `use:'sig'`.
   */
  jwks(): { keys: Array<Record<string, unknown>> } {
    const out: Array<Record<string, unknown>> = []
    for (const key of this._verifyKeys.values()) {
      const alg: JwtTransport.IJwtAlg = key.alg ?? 'HS256'
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
   */
  static mintFresh(transport: JwtTransport, sid: string, session: Session.ISession): Provider.Intent[] {
    return transport.issue(sid, session, { fresh: true, absolute: false })
  }

  /**
   * Live JWKS rotation. Promote a new signing key and (optionally) add
   * its public counterpart to the verify ring atomically. Older keys
   * stay in the ring under their original kid so already-issued tokens
   * keep verifying; operators retire them via `retireVerifyKey(kid)`
   * after their grace window elapses.
   */
  rotateSignKey(opts: JwtTransport.IRotateOpts): void {
    const newSign = opts.signKey
    const newAlg: JwtTransport.IJwtAlg = newSign.alg ?? 'HS256'
    if (opts.verifyKey) {
      const existing = this._verifyKeys.get(opts.verifyKey.kid)
      if (existing && (existing.alg ?? 'HS256') !== (opts.verifyKey.alg ?? 'HS256')) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
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

  /**
   * Remove a kid from the verify ring. Use after the grace window
   * expires so verifiers stop accepting tokens minted under the old
   * key. Refuses to remove the current signing kid.
   */
  retireVerifyKey(kid: string): void {
    if (kid === this._signKey.kid) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `retireVerifyKey: refusing to remove the active signing kid '${kid}'`,
      })
    }
    this._verifyKeys.delete(kid)
  }
}

// Re-export for parity with cookie/bearer transports.
export { randomToken, sha256 }

/**
 * Namespace merge for JwtTransport. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging.
 */
export namespace JwtTransport {
  export interface IConfig {
    /**
     * Active signing key. For HS256 the `key` is the secret; for ES256 /
     * RS256 it is the PEM-encoded PRIVATE key. `alg` defaults to HS256.
     */
    signKey: { kid: string; alg?: JwtTransport.IJwtAlg; key: string }
    /**
     * All currently-valid verify keys. Must contain `signKey`; during rotation,
     * the previous keys remain here for an overlap window so already-issued
     * tokens keep verifying.
     */
    verifyKeys: JwtTransport.IVerifyKey[]
    issuer: string
    audience?: string
    /** JWT TTL in ms. Default 15 minutes. */
    ttlMs?: number
    /**
     * Freshness window in ms. A JWT round-trip reconstructs the session
     * with `fresh = (now - rotatedAt) < freshnessMs`. Default 5 minutes,
     * matching `SessionsFacet.IConfig.freshnessMs`. Privileged
     * operations (password reset with TOTP, step-up-required actions)
     * branch on the `fresh` flag; setting this too high effectively
     * disables the freshness gate.
     */
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
    /**
     * Algorithm this key verifies. Default `'HS256'` for backwards
     * compatibility; ES256 + RS256 callers must set this explicitly.
     */
    alg?: JwtTransport.IJwtAlg
    /**
     * Key material. For `HS256`: the UTF-8 secret. For `ES256` / `RS256`:
     * the PEM-encoded public key (SPKI or RSA-PUBLIC).
     */
    key: string
    /** Optional rotation cutoff - verify-only after this. */
    notAfter?: number
  }

  export type IJwtAlg = 'HS256' | 'ES256' | 'RS256' | 'EdDSA'

  export interface IRotateOpts {
    /** New signing key. Becomes effective for all subsequent issue() calls. */
    signKey: { kid: string; alg?: IJwtAlg; key: string }
    /**
     * Optional verify-side entry for the new key. Required for
     * asymmetric algs since signKey carries the PRIVATE key and the
     * verify ring needs the PUBLIC counterpart.
     */
    verifyKey?: IVerifyKey
  }
}
