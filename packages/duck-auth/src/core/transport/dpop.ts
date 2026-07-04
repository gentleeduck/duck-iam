/**
 * DPoP (Demonstration of Proof-of-Possession) per RFC 9449. Verifies
 * the `DPoP` header on each authenticated request, binding a bearer
 * access token to a client-held private key.
 *
 * Threat addressed: a stolen bearer token alone is insufficient - the
 * attacker also needs the matching private key to mint a fresh DPoP
 * proof for each request.
 *
 * This module ships only the verifier surface; minting DPoP proofs is
 * a client-side concern that lives in `client/vanilla`.
 */

import { createHash, createPublicKey, createVerify, verify as cryptoVerify, type KeyObject } from 'node:crypto'
import { timingSafeEqual } from '../crypto'
import { AuthError } from '../errors'

export namespace AuthDPoPVerifier {
  /**
   * RFC 7517 JSON Web Key shape. Re-declared because Node's
   * @types/node does not export `JsonWebKey` from `node:crypto`.
   */
  export interface IJsonWebKey {
    kty: 'EC' | 'OKP' | 'RSA'
    crv?: string
    x?: string
    y?: string
    n?: string
    e?: string
    /** Private-key component; RFC 9449 forbids in proofs. */
    d?: string
    [key: string]: unknown
  }

  /**
   * Replay-protection store for DPoP `jti` claims. Each accepted proof
   * writes its `jti` for the freshness window so a captured proof
   * cannot be replayed.
   */
  export interface INonceStore {
    /**
     * Mark `jti` as seen. Returns true on first sight, false when the
     * jti was already recorded within the freshness window. Must be
     * atomic across concurrent callers.
     */
    recordSeen(jti: string, ttlMs: number): Promise<boolean>
  }

  /** Config knobs for {@link AuthDPoPVerifier}. */
  export interface IConfig {
    /** Tolerated clock skew between client + server, ms. Default 30s. */
    clockSkewMs?: number
    /**
     * Freshness window applied to `iat` (ms). Proofs older than this
     * (after subtracting clockSkew) are rejected. Default 60s.
     */
    freshnessMs?: number
    /**
     * Replay-protection store. Defaults to the in-memory implementation;
     * production wires a Redis-backed store.
     */
    nonceStore?: INonceStore
    /**
     * Allowed signing algorithms. Defaults to `['ES256', 'EdDSA']` -
     * symmetric algorithms are forbidden by RFC 9449 section 4.2.
     */
    acceptedAlgs?: Array<'ES256' | 'EdDSA' | 'RS256' | 'PS256'>
    /**
     * Server-supplied nonce challenge (RFC 9449 section 8/9). When set, the
     * proof's `nonce` claim MUST match. Pass a string for a static
     * nonce or a thunk that returns the current nonce (e.g. rotated
     * every minute). Useful for multi-pod deployments where jti store
     * latency makes the local replay window porous.
     */
    expectedNonce?: string | (() => Promise<string> | string)
  }

  /** Decoded DPoP proof claims. */
  export interface IClaims {
    /** Unique per-proof identifier; used for replay protection. */
    jti: string
    /** HTTP method, uppercased. */
    htm: string
    /** Absolute URL of the request, without query / fragment. */
    htu: string
    /** Issued-at, seconds since epoch. */
    iat: number
    /** Optional access-token hash (sha-256 base64url) bound to this proof. */
    ath?: string
    /** Optional server-supplied nonce echoed back for additional replay protection. */
    nonce?: string
  }

  /** Result of a successful verify call. */
  export interface IVerified {
    /** RFC 7638 JWK thumbprint of the client's public key. */
    jkt: string
    /** The verified claims. */
    claims: IClaims
  }
}

/**
 * In-memory nonce store. Single-process only; multi-pod deploys must
 * wire a Redis-backed store using `SETNX` for true atomic claim.
 */
export class AuthMemoryDPoPNonceStore implements AuthDPoPVerifier.INonceStore {
  private readonly _seen = new Map<string, number>()

  /** Mark `jti`. Lazy prune assumes uniform TTL; cross-TTL stragglers fail closed (false-positive). */
  async recordSeen(jti: string, ttlMs: number): Promise<boolean> {
    const now = Date.now()
    for (const [k, expiresAt] of this._seen) {
      if (expiresAt < now) {
        this._seen.delete(k)
        continue
      }
      break
    }
    if (this._seen.has(jti)) return false
    this._seen.set(jti, now + ttlMs)
    return true
  }
}

/**
 * Per-request DPoP verifier. Stateless apart from the configured nonce
 * store. Throws `AUTH/DPOP_INVALID` on any failure so the framework
 * adapter can wrap calls in a single try/catch.
 */
export class AuthDPoPVerifier {
  private readonly _clockSkewMs: number
  private readonly _freshnessMs: number
  private readonly _nonceStore: AuthDPoPVerifier.INonceStore
  private readonly _expectedNonce: AuthDPoPVerifier.IConfig['expectedNonce']
  private readonly _acceptedAlgs: Set<string>

  constructor(cfg: AuthDPoPVerifier.IConfig = {}) {
    this._clockSkewMs = cfg.clockSkewMs ?? 30_000
    this._freshnessMs = cfg.freshnessMs ?? 60_000
    this._nonceStore = cfg.nonceStore ?? new AuthMemoryDPoPNonceStore()
    this._expectedNonce = cfg.expectedNonce
    this._acceptedAlgs = new Set(cfg.acceptedAlgs ?? ['ES256', 'EdDSA'])
  }

  /**
   * Verify the `DPoP` header against the request. Returns
   * `{ jkt, claims }` on success; throws `AUTH/DPOP_INVALID` otherwise.
   */
  async verify(
    dpopHeader: string,
    request: { method: string; url: string },
    accessToken?: string,
  ): Promise<AuthDPoPVerifier.IVerified> {
    if (typeof dpopHeader !== 'string' || dpopHeader.length === 0) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'missing DPoP header' })
    }
    if (dpopHeader.length > 8192) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'DPoP header too large' })
    }
    const [headerB64, payloadB64, sig, ...rest] = dpopHeader.split('.')
    if (rest.length > 0 || headerB64 === undefined || payloadB64 === undefined || sig === undefined) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'malformed JWS' })
    }

    const parsedHeader = parseDpopHeader(decodeJson(headerB64), this._acceptedAlgs)
    if (!parsedHeader.ok) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: parsedHeader.reason })
    }
    const header = parsedHeader.value

    let publicKey: KeyObject
    try {
      publicKey = createPublicKey({ key: header.jwk, format: 'jwk' })
    } catch {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'jwk is not a valid public key' })
    }

    if (!verifyJws(header.alg, publicKey, `${headerB64}.${payloadB64}`, sig)) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'signature verification failed' })
    }

    const parsedClaims = parseDpopClaims(decodeJson(payloadB64))
    if (!parsedClaims.ok) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: parsedClaims.reason })
    }
    const claims = parsedClaims.value

    if (claims.htm.toUpperCase() !== request.method.toUpperCase()) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'htm mismatch' })
    }
    if (normalizeUrl(claims.htu) !== normalizeUrl(request.url)) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'htu mismatch' })
    }
    // RFC 9449 4.2 freshness window; parser already rejects non-finite iat.
    const nowMs = Date.now()
    const iatMs = claims.iat * 1000
    if (Math.abs(nowMs - iatMs) > this._clockSkewMs + this._freshnessMs) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'proof outside freshness window' })
    }

    // RFC 9449 section 4.3: bind the proof to the access token via `ath` when
    // one is present; refuse a stray `ath` when it is not.
    if (accessToken !== undefined) {
      if (typeof accessToken !== 'string' || accessToken.length === 0 || accessToken.length > 4096) {
        throw new AuthError('AUTH_DPOP_INVALID', { reason: 'access token too large or invalid' })
      }
      if (!claims.ath) {
        throw new AuthError('AUTH_DPOP_INVALID', { reason: 'ath required when access token present' })
      }
      const expected = sha256base64url(accessToken)
      // timingSafeEqual defense-in-depth (signature still gates).
      if (!timingSafeEqual(claims.ath, expected)) {
        throw new AuthError('AUTH_DPOP_INVALID', { reason: 'ath mismatch' })
      }
    } else if (claims.ath !== undefined) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'ath unexpected (no access token in request)' })
    }

    // Server nonce challenge (RFC 9449 8/9); tightens replay across partitioned deploys.
    if (this._expectedNonce !== undefined) {
      const expectedNonce =
        typeof this._expectedNonce === 'function' ? await this._expectedNonce() : this._expectedNonce
      // timingSafeEqual so `!==` does not leak the nonce byte-by-byte.
      if (claims.nonce === undefined || !timingSafeEqual(claims.nonce, expectedNonce)) {
        throw new AuthError('AUTH_DPOP_INVALID', { reason: 'nonce mismatch' })
      }
    }

    const fresh = await this._nonceStore.recordSeen(claims.jti, this._freshnessMs + this._clockSkewMs)
    if (!fresh) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'jti replay detected' })
    }

    return { jkt: authComputeJwkThumbprint(header.jwk), claims }
  }
}

/**
 * Compute the RFC 7638 JWK thumbprint of a public key. Used to bind a
 * DPoP proof's JWK to the `cnf.jkt` claim on the access token.
 */
export function authComputeJwkThumbprint(jwk: AuthDPoPVerifier.IJsonWebKey): string {
  let canonical: string
  switch (jwk.kty) {
    case 'EC':
      canonical = JSON.stringify({ crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y })
      break
    case 'OKP':
      canonical = JSON.stringify({ crv: jwk.crv, kty: 'OKP', x: jwk.x })
      break
    case 'RSA':
      canonical = JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n })
      break
    default:
      throw new AuthError('AUTH_DPOP_INVALID', { reason: `unsupported kty ${String(jwk.kty)}` })
  }
  return createHash('sha256').update(canonical).digest('base64url')
}

/**
 * Internal parser result. Discriminated so callers narrow without casts.
 * `reason` is surfaced as the `AuthError` meta on failure.
 */
type ParseResult<T> = { ok: true; value: T } | { ok: false; reason: string }

interface DpopHeaderShape {
  alg: string
  typ: 'dpop+jwt'
  jwk: AuthDPoPVerifier.IJsonWebKey
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isJsonWebKey(v: unknown): v is AuthDPoPVerifier.IJsonWebKey {
  if (!isPlainObject(v)) return false
  return v.kty === 'EC' || v.kty === 'OKP' || v.kty === 'RSA'
}

/** Validate the decoded DPoP header. */
function parseDpopHeader(raw: unknown, acceptedAlgs: ReadonlySet<string>): ParseResult<DpopHeaderShape> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: 'bad typ; expected dpop+jwt' }
  }
  const { alg, typ, jwk } = raw
  if (typ !== 'dpop+jwt') {
    return { ok: false, reason: 'bad typ; expected dpop+jwt' }
  }
  if (typeof alg !== 'string' || !acceptedAlgs.has(alg)) {
    return { ok: false, reason: `alg ${typeof alg === 'string' ? alg : '?'} not accepted` }
  }
  if (!isJsonWebKey(jwk)) {
    return { ok: false, reason: 'missing jwk' }
  }
  if (jwk.d !== undefined) {
    return { ok: false, reason: 'jwk contains private key material' }
  }
  return { ok: true, value: { alg, typ, jwk } }
}

/**
 * validate the decoded DPoP claims without `as` casts. Each field
 * is narrowed by `typeof` before use so a malformed proof cannot
 * (a) bypass freshness via `NaN > N === false` on a non-numeric `iat`,
 * (b) crash the verifier via `.toUpperCase()` on a non-string `htm`,
 * (c) crash via `new URL(obj)` on a non-string `htu`, or
 * (d) sneak through `ath`/`nonce` value-equality checks with object
 *     identity.
 */
function parseDpopClaims(raw: unknown): ParseResult<AuthDPoPVerifier.IClaims> {
  if (!isPlainObject(raw)) {
    return { ok: false, reason: 'malformed payload' }
  }
  const { jti, htm, htu, iat, ath, nonce } = raw
  if (typeof jti !== 'string' || jti.length === 0) {
    return { ok: false, reason: 'missing jti' }
  }
  if (typeof htm !== 'string') {
    return { ok: false, reason: 'htm missing or not a string' }
  }
  if (typeof htu !== 'string') {
    return { ok: false, reason: 'htu missing or not a string' }
  }
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    return { ok: false, reason: 'iat missing or not a finite number' }
  }
  if (ath !== undefined && typeof ath !== 'string') {
    return { ok: false, reason: 'ath not a string' }
  }
  if (nonce !== undefined && typeof nonce !== 'string') {
    return { ok: false, reason: 'nonce not a string' }
  }
  const claims: AuthDPoPVerifier.IClaims = { jti, htm, htu, iat }
  if (ath !== undefined) claims.ath = ath
  if (nonce !== undefined) claims.nonce = nonce
  return { ok: true, value: claims }
}

/**
 * Inject a `cnf.jkt` confirmation claim into an existing access-token
 * payload object.
 */
export function authBindPayloadToDPoP<P extends Record<string, unknown>>(
  payload: P,
  jkt: string,
): P & { cnf: { jkt: string } } {
  return { ...payload, cnf: { jkt } }
}

function decodeJson(b64: string): unknown {
  try {
    return JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'))
  } catch {
    return null
  }
}

function sha256base64url(s: string): string {
  return createHash('sha256').update(s).digest('base64url')
}

function normalizeUrl(raw: string): string {
  try {
    const u = new URL(raw)
    u.hash = ''
    u.search = ''
    return u.toString().replace(/\/$/, '')
  } catch {
    return raw
  }
}

function verifyJws(alg: string, key: KeyObject, signingInput: string, signatureB64: string): boolean {
  const signature = Buffer.from(signatureB64, 'base64url')
  try {
    switch (alg) {
      case 'ES256': {
        const der = joseToDer(signature, 32)
        const v = createVerify('SHA256')
        v.update(signingInput)
        v.end()
        return v.verify(key, der)
      }
      case 'RS256': {
        const v = createVerify('RSA-SHA256')
        v.update(signingInput)
        v.end()
        return v.verify(key, signature)
      }
      case 'PS256': {
        const v = createVerify('RSA-SHA256')
        v.update(signingInput)
        v.end()
        return v.verify({ key, padding: 6 }, signature)
      }
      case 'EdDSA': {
        return cryptoVerify(null, Buffer.from(signingInput), key, signature)
      }
      default:
        return false
    }
  } catch {
    return false
  }
}

function joseToDer(raw: Buffer, halfLen: number): Buffer {
  if (raw.length !== halfLen * 2) {
    throw new AuthError('AUTH_DPOP_INVALID', { reason: 'malformed ES256 signature length' })
  }
  const r = trimLeadingZeros(raw.subarray(0, halfLen))
  const s = trimLeadingZeros(raw.subarray(halfLen))
  const rEnc = encodeInteger(r)
  const sEnc = encodeInteger(s)
  const total = rEnc.length + sEnc.length
  return Buffer.concat([Buffer.from([0x30, total]), rEnc, sEnc])
}

function trimLeadingZeros(buf: Buffer): Buffer {
  let i = 0
  while (i < buf.length - 1 && buf[i] === 0) i++
  return buf.subarray(i)
}

function encodeInteger(buf: Buffer): Buffer {
  const needsPad = (buf[0] ?? 0) & 0x80
  const body = needsPad ? Buffer.concat([Buffer.from([0]), buf]) : buf
  return Buffer.concat([Buffer.from([0x02, body.length]), body])
}
