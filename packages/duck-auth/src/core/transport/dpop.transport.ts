/** DPoP per RFC 9449: verifies the `DPoP` header on each request so a stolen bearer token is not enough
 *  on its own - provided the caller compares the returned `jkt` against the token's `cnf.jkt`, which
 *  see. The verifier surface only; minting proofs lives in `client/vanilla`. */

import { createHash, createPublicKey, createVerify, verify as cryptoVerify, type KeyObject } from 'node:crypto'
import { timingSafeEqual } from '../crypto'
import { AuthError } from '../errors'
import { MemoryDPoPNonceStore } from './dpop-nonce.memory'

/** Each half of the window. Past an hour a proof is not "recently created" in any sense RFC 9449 means.
 *  A proof is accepted from `iat - (clockSkew + freshness)` to `iat + (clockSkew + freshness)`, so the
 *  window is twice this and the replay TTL is measured against its far edge, not against the sum. */
const WINDOW_MAX_MS = 3_600_000

export namespace DPoPVerifier {
  /** RFC 7517, re-declared because @types/node does not export `JsonWebKey` from `node:crypto`. */
  export type JsonWebKey = {
    kty: 'EC' | 'OKP' | 'RSA'
    crv?: string
    x?: string
    y?: string
    n?: string
    e?: string
    /** A private-key component, which RFC 9449 forbids in a proof. */
    d?: string
    [key: string]: unknown
  }

  /** Replay protection for DPoP `jti` claims: each accepted proof writes its `jti` for the freshness
   *  window, so a captured proof cannot be replayed. */
  export interface NonceStore {
    /** Mark `jti` as seen: true on first sight, false while the prior record is still alive. The
     *  verifier asks for exactly as long as the proof stays acceptable, so honour `ttlMs` per key
     *  rather than assuming one global window. Must be atomic across concurrent callers. */
    recordSeen(jti: string, ttlMs: number): Promise<boolean>
  }

  export interface Cfg {
    /** Tolerated clock skew between client and server, ms. Default 30s. */
    clockSkewMs?: number
    /** Applied to `iat` in ms, after `clockSkewMs` is subtracted. Default 60s. */
    freshnessMs?: number
    /** In-memory by default; production wires the Redis-backed store. */
    nonceStore?: NonceStore
    /** `['ES256', 'EdDSA']` by default, RFC 9449 section 4.2 forbidding symmetric algorithms. */
    acceptedAlgs?: Array<'ES256' | 'EdDSA' | 'RS256' | 'PS256'>
    /** RFC 9449 §8-9: when set, the proof's `nonce` must match. A string for a static one, a thunk for a
     *  rotating one, which helps where jti-store latency leaves a local replay window porous. */
    expectedNonce?: string | (() => Promise<string> | string)
  }

  export interface Claims {
    /** Unique per proof, and what replay protection is keyed on. */
    jti: string
    /** HTTP method, uppercased. */
    htm: string
    /** Absolute URL of the request, with no query or fragment. */
    htu: string
    /** Issued-at, seconds since epoch. */
    iat: number
    /** Access-token hash, sha-256 base64url, bound to this proof. */
    ath?: string
    /** Optional server-supplied nonce echoed back for additional replay protection. */
    nonce?: string
  }

  export interface Verified {
    /** RFC 7638 JWK thumbprint of the key that signed this proof.
     *
     *  SECURITY: compare it against the access token's `cnf.jkt` - the one written by
     *  {@link bindPayloadToDPoP} - before honouring the request. A proof carries the key it was signed
     *  with, so the presenter always holds the key in the proof; whether it is the key the token was
     *  issued against is the question, and this value is the whole answer. Skip the comparison and a
     *  `verify` that does not throw means only that someone signed a well-formed proof over this token
     *  for this URL, which whoever stole the token can do with a keypair of their own. */
    jkt: string
    claims: Claims
  }
}

/** Per-request DPoP verifier, stateless apart from the nonce store. Throws `AUTH_DPOP_INVALID` on
 *  any failure, so an adapter wraps it in one try/catch. */
export class DPoPVerifier {
  private readonly _clockSkewMs: number
  private readonly _freshnessMs: number
  private readonly _nonceStore: DPoPVerifier.NonceStore
  private readonly _expectedNonce: DPoPVerifier.Cfg['expectedNonce']
  private readonly _acceptedAlgs: Set<string>

  constructor(cfg: DPoPVerifier.Cfg = {}) {
    this._clockSkewMs = cfg.clockSkewMs ?? 30_000
    this._freshnessMs = cfg.freshnessMs ?? 60_000
    this._nonceStore = cfg.nonceStore ?? new MemoryDPoPNonceStore()
    this._expectedNonce = cfg.expectedNonce
    this._acceptedAlgs = new Set(cfg.acceptedAlgs ?? ['ES256', 'EdDSA'])
    // SECURITY: the freshness window is `Math.abs(now - iat) > clockSkew + freshness`, and `>` against a
    // sum that is not a number is false, so the check never fires. Measured: a `clockSkewMs` of NaN
    // accepted proofs dated a year old, ten years old, and a year in the future. The parser refuses a
    // non-finite `iat` and says so above that comparison - the claim an attacker controls was bounded,
    // the two numbers it is weighed against were not.
    if (!Number.isFinite(this._clockSkewMs) || this._clockSkewMs < 0 || this._clockSkewMs > WINDOW_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `DPoPVerifier: clockSkewMs must be a number between 0 and ${WINDOW_MAX_MS} (got ${this._clockSkewMs})`,
      })
    }
    if (!Number.isFinite(this._freshnessMs) || this._freshnessMs < 0 || this._freshnessMs > WINDOW_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `DPoPVerifier: freshnessMs must be a number between 0 and ${WINDOW_MAX_MS} (got ${this._freshnessMs})`,
      })
    }
  }

  /** Verifies the proof against this method and URL; comparing its `jkt` is the caller's job. */
  async verify(
    dpopHeader: string,
    request: { method: string; url: string },
    accessToken?: string,
  ): Promise<DPoPVerifier.Verified> {
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
    const window = this._clockSkewMs + this._freshnessMs
    if (Math.abs(nowMs - iatMs) > window) {
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
      // timingSafeEqual as defence in depth; the signature still gates.
      if (!timingSafeEqual(claims.ath, expected)) {
        throw new AuthError('AUTH_DPOP_INVALID', { reason: 'ath mismatch' })
      }
    } else if (claims.ath !== undefined) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'ath unexpected (no access token in request)' })
    }

    // RFC 9449 8/9, which tightens replay across partitioned deploys.
    if (this._expectedNonce !== undefined) {
      const expectedNonce =
        typeof this._expectedNonce === 'function' ? await this._expectedNonce() : this._expectedNonce
      // timingSafeEqual so `!==` does not leak the nonce byte-by-byte.
      if (claims.nonce === undefined || !timingSafeEqual(claims.nonce, expectedNonce)) {
        throw new AuthError('AUTH_DPOP_INVALID', { reason: 'nonce mismatch' })
      }
    }

    // SECURITY: held until this proof stops being acceptable, which is `iat + window` and not `window`
    // from now. The check above is two-sided, so a proof dated into the future - which is what
    // `clockSkewMs` exists to tolerate, and every client whose clock runs fast mints one - is accepted
    // before its `iat` and stays acceptable well after the jti was forgotten. Measured at the defaults:
    // the verifier asked for a 90s TTL on a proof that stayed fresh for another 179s, and the identical
    // proof, replayed once its jti had expired, was accepted a second time. The gap is how far ahead the
    // client's clock runs, up to the full 90s.
    const fresh = await this._nonceStore.recordSeen(claims.jti, iatMs + window - nowMs)
    if (!fresh) {
      throw new AuthError('AUTH_DPOP_INVALID', { reason: 'jti replay detected' })
    }

    return { jkt: computeJwkThumbprint(header.jwk), claims }
  }
}

/** RFC 7638, which is what binds a proof's JWK to the access token's `cnf.jkt` claim. */
export function computeJwkThumbprint(jwk: DPoPVerifier.JsonWebKey): string {
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

/** Discriminated, so callers narrow without casts. `reason` becomes the `AuthError` meta on failure. */
type ParseResult<T> = { ok: true; value: T } | { ok: false; reason: string }

interface DpopHeaderShape {
  alg: string
  typ: 'dpop+jwt'
  jwk: DPoPVerifier.JsonWebKey
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isJsonWebKey(v: unknown): v is DPoPVerifier.JsonWebKey {
  if (!isPlainObject(v)) return false
  return v.kty === 'EC' || v.kty === 'OKP' || v.kty === 'RSA'
}

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

/** Validate the decoded DPoP claims, narrowing each field by `typeof` first: a non-numeric `iat`
 *  would bypass freshness through `NaN > N === false`, and a non-string `htm`/`htu` would crash the
 *  verifier outright. */
function parseDpopClaims(raw: unknown): ParseResult<DPoPVerifier.Claims> {
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
  const claims: DPoPVerifier.Claims = { jti, htm, htu, iat }
  if (ath !== undefined) claims.ath = ath
  if (nonce !== undefined) claims.nonce = nonce
  return { ok: true, value: claims }
}

/** Injects a `cnf.jkt` confirmation claim into an existing access-token payload. */
export function bindPayloadToDPoP<P extends Record<string, unknown>>(
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

/** Constructs a {@link DPoPVerifier}. */
export function dPoPVerifier(...args: ConstructorParameters<typeof DPoPVerifier>): DPoPVerifier {
  return new DPoPVerifier(...args)
}
