import { scrypt as nodeScrypt, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'
import type { Hasher } from '../types/hasher'

const scryptAsync = promisify(nodeScrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem?: number },
) => Promise<Buffer>

/** Default parameters tuned for ~150 ms on a 2022-class server CPU. */
export const SCRYPT_DEFAULTS: ScryptHasher.IScryptParams = {
  N: 1 << 17,
  r: 8,
  p: 1,
  keylen: 64,
  saltLen: 16,
}

/**
 * Encoded format: `scrypt$<N>$<r>$<p>$<saltBase64>$<keyBase64>`.
 * All fields URL-safe base64. Self-describing so we can detect parameter
 * drift in {@link needsRehash} without an external migration table.
 */
function encode(N: number, r: number, p: number, salt: Buffer, key: Buffer): string {
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64url')}$${key.toString('base64url')}`
}

function parse(encoded: string): { N: number; r: number; p: number; salt: Buffer; key: Buffer } | null {
  const parts = encoded.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null
  const [_, Nstr, rStr, pStr, saltB64, keyB64] = parts
  const N = Number(Nstr)
  const r = Number(rStr)
  const p = Number(pStr)
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return null
  if (N < 2 || (N & (N - 1)) !== 0) return null // must be power of two
  return {
    N,
    r,
    p,
    salt: Buffer.from(saltB64 ?? '', 'base64url'),
    key: Buffer.from(keyB64 ?? '', 'base64url'),
  }
}

/**
 * ScryptHasher - built into Node, zero deps. v0.1 default.
 *
 * Trade-offs vs Argon2id:
 *  - scrypt does not have the memory-hard "lanes" parameter (no `p` analogue
 *    for true thread parallelism on a single hash)
 *  - constant-time verify via `timingSafeEqual` on the derived key
 *  - format is self-describing for future param rotation
 *
 * Compliance presets (HIPAA/SOC2/FIPS in v1.x) require swapping this for
 * Argon2id; that lands in `core/password/argon2.ts` as a sibling impl.
 */
export class ScryptHasher implements Hasher.IHasher {
  readonly id = 'scrypt'
  private readonly _params: ScryptHasher.IScryptParams

  constructor(params: Partial<ScryptHasher.IScryptParams> = {}) {
    this._params = { ...SCRYPT_DEFAULTS, ...params }
  }

  async hash(plaintext: string): Promise<string> {
    const salt = randomBytes(this._params.saltLen)
    const key = await scryptAsync(plaintext, salt, this._params.keylen, {
      N: this._params.N,
      r: this._params.r,
      p: this._params.p,
      maxmem: 256 * 1024 * 1024, // 256 MB ceiling - keeps headroom over N=2^17
    })
    return encode(this._params.N, this._params.r, this._params.p, salt, key)
  }

  async verify(plaintext: string, encoded: string): Promise<boolean> {
    const parsed = parse(encoded)
    if (!parsed) return false
    try {
      const candidate = await scryptAsync(plaintext, parsed.salt, parsed.key.length, {
        N: parsed.N,
        r: parsed.r,
        p: parsed.p,
        maxmem: 256 * 1024 * 1024,
      })
      if (candidate.length !== parsed.key.length) return false
      return timingSafeEqual(candidate, parsed.key)
    } catch {
      return false
    }
  }

  needsRehash(encoded: string): boolean {
    const parsed = parse(encoded)
    if (!parsed) return true
    return (
      parsed.N < this._params.N ||
      parsed.r < this._params.r ||
      parsed.p < this._params.p ||
      parsed.key.length < this._params.keylen
    )
  }
}

/**
 * Namespace merge for `ScryptHasher`. Co-locates the flat type exports
 * alongside the primary symbol via TS class+namespace merging.
 */
export namespace ScryptHasher {
  export interface IScryptParams {
    /** CPU/memory cost (must be a power of two). Default 2^17 = 131072. */
    N: number
    /** Block size. Default 8. */
    r: number
    /** Parallelisation. Default 1. */
    p: number
    /** Derived-key length, bytes. Default 64. */
    keylen: number
    /** Salt length, bytes. Default 16. */
    saltLen: number
  }
}
