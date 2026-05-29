/**
 * @packageDocumentation
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createHash, createPublicKey, createVerify, verify as cryptoVerify, type KeyObject } from 'node:crypto'
import { AuthErrorObject } from '../errors'

/**
 * RFC 7517 JSON Web Key shape. Re-declared here because Node's
 * @types/node does not export `JsonWebKey` as a named member from
 * `node:crypto`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface DPoPJsonWebKey {
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
 * Replay-protection store for DPoP `jti` (JWT id) claims. Each accepted
 * proof writes its `jti` for `windowSec` so an attacker who captures a
 * proof in transit cannot replay it inside the freshness window.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface DPoPNonceStore {
  /**
   * Mark a `jti` as seen. Returns true on first sight, false when the
   * `jti` was already recorded within the freshness window. Must be
   * atomic across concurrent callers (Redis SETNX in production).
   */
  recordSeen(jti: string, ttlMs: number): Promise<boolean>
}

/**
 * In-memory nonce store. Single-process only; multi-pod deploys must
 * wire a Redis-backed store using `SETNX` for true atomic claim.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class MemoryDPoPNonceStore implements DPoPNonceStore {
  private readonly _seen = new Map<string, number>()

  /**
   * Mark a `jti`. Lazily prunes the map on each call so memory growth
   * is bounded by the freshness window plus epsilon.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async recordSeen(jti: string, ttlMs: number): Promise<boolean> {
    const now = Date.now()
    for (const [k, expiresAt] of this._seen) {
      if (expiresAt < now) this._seen.delete(k)
    }
    if (this._seen.has(jti)) return false
    this._seen.set(jti, now + ttlMs)
    return true
  }
}

export interface DPoPVerifierConfig {
  /**
   * Tolerated clock skew between client + server, ms. The proof's `iat`
   * claim must fall in `[now - clockSkew - window, now + clockSkew]`.
   * Default 30 seconds.
   */
  clockSkewMs?: number
  /**
   * Freshness window applied to `iat` (ms). Proofs older than this
   * (after subtracting `clockSkewMs`) are rejected. Default 60 seconds.
   */
  freshnessMs?: number
  /**
   * Replay-protection store. Defaults to the in-memory implementation;
   * production must wire a Redis-backed store.
   */
  nonceStore?: DPoPNonceStore
  /**
   * Allowed signing algorithms. Defaults to `['ES256', 'EdDSA']` -
   * symmetric algorithms are forbidden by RFC 9449 section 4.2.
   */
  acceptedAlgs?: Array<'ES256' | 'EdDSA' | 'RS256' | 'PS256'>
}

/**
 * Decoded DPoP proof claims. The verifier reconstructs this from the
 * `DPoP` header on each verified request.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface DPoPClaims {
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

/**
 * Result of a successful DPoP proof verification. Callers cross-check
 * `jkt` against `cnf.jkt` on the access token (see `bindAccessTokenToDPoP`)
 * to confirm the proof + token were issued together.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface DPoPVerified {
  /** RFC 7638 JWK thumbprint of the client's public key. */
  jkt: string
  /** The verified claims. */
  claims: DPoPClaims
}

/**
 * Per-request DPoP verifier. Stateless apart from the configured nonce
 * store. Throws `AUTH/DPOP_INVALID` on any failure so the framework
 * adapter can wrap calls in a single try/catch.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class DPoPVerifier {
  private readonly _clockSkewMs: number
  private readonly _freshnessMs: number
  private readonly _nonceStore: DPoPNonceStore
  private readonly _acceptedAlgs: Set<string>

  constructor(cfg: DPoPVerifierConfig = {}) {
    this._clockSkewMs = cfg.clockSkewMs ?? 30_000
    this._freshnessMs = cfg.freshnessMs ?? 60_000
    this._nonceStore = cfg.nonceStore ?? new MemoryDPoPNonceStore()
    this._acceptedAlgs = new Set(cfg.acceptedAlgs ?? ['ES256', 'EdDSA'])
  }

  /**
   * Verify the `DPoP` header against the request. Returns `{ jkt, claims }`
   * on success; throws `AUTH/DPOP_INVALID` otherwise.
   *
   * @param dpopHeader raw `DPoP` header value
   * @param request canonical request shape (method + absolute URL)
   * @param accessToken optional bearer token; when supplied, `ath` claim
   *                    is required + compared
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async verify(
    dpopHeader: string,
    request: { method: string; url: string },
    accessToken?: string,
  ): Promise<DPoPVerified> {
    if (!dpopHeader) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'missing DPoP header' })
    }
    const parts = dpopHeader.split('.')
    if (parts.length !== 3) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'malformed JWS' })
    }
    const [headerB64, payloadB64, sig] = parts as [string, string, string]

    const header = decodeJson(headerB64) as { alg?: string; typ?: string; jwk?: DPoPJsonWebKey }
    if (!header || header.typ !== 'dpop+jwt') {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'bad typ; expected dpop+jwt' })
    }
    if (!header.alg || !this._acceptedAlgs.has(header.alg)) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: `alg ${header.alg ?? '?'} not accepted` })
    }
    if (!header.jwk || typeof header.jwk !== 'object') {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'missing jwk' })
    }
    if ((header.jwk as { d?: unknown }).d !== undefined) {
      // RFC 9449 4.2 - proofs MUST NOT include the private key.
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'jwk contains private key material' })
    }

    let publicKey: KeyObject
    try {
      publicKey = createPublicKey({ key: header.jwk, format: 'jwk' })
    } catch {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'jwk is not a valid public key' })
    }

    if (!verifyJws(header.alg, publicKey, `${headerB64}.${payloadB64}`, sig)) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'signature verification failed' })
    }

    const claims = decodeJson(payloadB64) as DPoPClaims | null
    if (!claims) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'malformed payload' })
    }
    if (!claims.jti || typeof claims.jti !== 'string') {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'missing jti' })
    }
    if (!claims.htm || claims.htm.toUpperCase() !== request.method.toUpperCase()) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'htm mismatch' })
    }
    if (!claims.htu || normalizeUrl(claims.htu) !== normalizeUrl(request.url)) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'htu mismatch' })
    }
    const nowMs = Date.now()
    const iatMs = claims.iat * 1000
    if (Math.abs(nowMs - iatMs) > this._clockSkewMs + this._freshnessMs) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'proof outside freshness window' })
    }

    if (accessToken) {
      const expected = sha256base64url(accessToken)
      if (claims.ath !== expected) {
        throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'ath mismatch' })
      }
    }

    const fresh = await this._nonceStore.recordSeen(claims.jti, this._freshnessMs + this._clockSkewMs)
    if (!fresh) {
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'jti replay detected' })
    }

    return { jkt: computeJwkThumbprint(header.jwk), claims }
  }
}

/**
 * Compute the RFC 7638 JWK thumbprint of a public key. Used to bind a
 * DPoP proof's JWK to the `cnf.jkt` claim on the access token.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function computeJwkThumbprint(jwk: DPoPJsonWebKey): string {
  const j = jwk as Record<string, unknown>
  let canonical: string
  switch (j.kty) {
    case 'EC':
      canonical = JSON.stringify({ crv: j.crv, kty: 'EC', x: j.x, y: j.y })
      break
    case 'OKP':
      canonical = JSON.stringify({ crv: j.crv, kty: 'OKP', x: j.x })
      break
    case 'RSA':
      canonical = JSON.stringify({ e: j.e, kty: 'RSA', n: j.n })
      break
    default:
      throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: `unsupported kty ${String(j.kty)}` })
  }
  return createHash('sha256').update(canonical).digest('base64url')
}

/**
 * Inject a `cnf.jkt` confirmation claim into an existing access-token
 * payload object. Use this when issuing the access token alongside a
 * DPoP-aware client so subsequent verifies can cross-check.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
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
        // Node expects DER-encoded ECDSA sigs; DPoP carries the raw r||s form.
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
        return v.verify({ key, padding: 6 /* RSA_PKCS1_PSS_PADDING */ }, signature)
      }
      case 'EdDSA': {
        // Node verify() supports Ed25519 with a null algorithm.
        return cryptoVerify(null, Buffer.from(signingInput), key, signature)
      }
      default:
        return false
    }
  } catch {
    return false
  }
}

/** Convert a raw r||s JOSE signature (P-256, 64 bytes) to DER. */
function joseToDer(raw: Buffer, halfLen: number): Buffer {
  if (raw.length !== halfLen * 2) {
    throw new AuthErrorObject('AUTH/DPOP_INVALID', { reason: 'malformed ES256 signature length' })
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

/**
 * Namespace merge for `DPoPVerifier`. Co-locates config + claim shapes
 * alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace DPoPVerifier {
  /** Alias for `DPoPVerifierConfig`. */
  export type IConfig = DPoPVerifierConfig
  /** Alias for `DPoPClaims`. */
  export type IClaims = DPoPClaims
  /** Alias for `DPoPVerified`. */
  export type IVerified = DPoPVerified
  /** Alias for the flat `DPoPJsonWebKey` type. */
  export type IDPoPJsonWebKey = DPoPJsonWebKey
  /** Alias for the flat `DPoPNonceStore` type. */
  export type IDPoPNonceStore = DPoPNonceStore
}
